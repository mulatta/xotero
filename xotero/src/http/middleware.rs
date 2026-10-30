use std::io::Read;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use axum::{
    body::{Body, Bytes, HttpBody},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

use crate::domain::{LibraryAccess, RequestContext};
use crate::error::server_error;
use crate::http::access::request_access_scope;
use crate::http::validation::{
    is_attachment_permission_path, is_group_discovery_path, path_group_data_id, path_user_id,
    request_log_path,
};
use crate::{store, AppState};

/// Encoded and decoded attachment/API body bound.
pub(crate) const MAX_BODY: usize = 256 * 1024 * 1024;
const MAX_PUBLIC_BODY: usize = 1024 * 1024;

// Admission precedes collection and spawning. The blocking job owns the permit:
// dropping its requesting future cannot admit another decoder while it runs.
static DECODERS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(4)));

pub(crate) async fn buffered_body(
    mut body: Body,
    headers: &HeaderMap,
    limit: usize,
) -> Result<Bytes, StatusCode> {
    let gzip = match headers.get("content-encoding") {
        None => false,
        Some(value) if value.as_bytes().eq_ignore_ascii_case(b"gzip") => true,
        Some(value) if value.as_bytes().eq_ignore_ascii_case(b"identity") => false,
        Some(_) => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    };
    let permit = if gzip {
        Some(
            Arc::clone(&DECODERS)
                .acquire_owned()
                .await
                .map_err(|error| {
                    tracing::error!(%error, "decoder admission failed");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?,
        )
    } else {
        None
    };
    let mut raw = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(data) = frame.into_data() {
            let remaining = (limit + 1).saturating_sub(raw.len());
            raw.extend_from_slice(&data[..data.len().min(remaining)]);
            if raw.len() > limit {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
    }
    let Some(permit) = permit else {
        return Ok(Bytes::from(raw));
    };
    spawn_decoder(std::io::Cursor::new(raw), limit, permit).await
}

async fn spawn_decoder(
    raw: impl Read + Send + 'static,
    limit: usize,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Bytes, StatusCode> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        decode_gzip(raw, limit)
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "request decoder failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
}

fn decode_gzip(raw: impl Read, limit: usize) -> Result<Bytes, StatusCode> {
    // MultiGzDecoder validates every member and its trailer; an exact boundary
    // still reads through EOF, while max+1 detects expansion without truncation.
    let mut decoder = flate2::read::MultiGzDecoder::new(raw)
        .take(u64::try_from(limit + 1).map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if out.len() > limit {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok(Bytes::from(out))
}

/// Resolve static recovery keys and database-owned keys against live identity
/// state. Database errors remain errors so an outage cannot masquerade as a bad
/// credential.
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
) -> sqlx::Result<Option<RequestContext>> {
    let Some(token) = headers
        .get("zotero-api-key")
        .and_then(|v| v.to_str().ok())
        .filter(|token| !token.is_empty())
    else {
        return Ok(None);
    };

    let digest = Sha256::digest(token.as_bytes());
    if let Some(permissions) = state.config.recovery_permissions(&digest) {
        return Ok(
            store::bootstrap_principal(&state.pool, state.config.user_id)
                .await?
                .map(|principal| RequestContext {
                    presented_key: token.to_owned(),
                    principal,
                    permissions,
                    api_key_id: None,
                }),
        );
    }

    Ok(store::authenticate_api_key(&state.pool, digest.as_slice())
        .await?
        .map(|(api_key_id, principal, permissions)| RequestContext {
            presented_key: token.to_owned(),
            principal,
            permissions,
            api_key_id: Some(api_key_id),
        }))
}

/// Decode gzip write bodies, log safe routing metadata, and reject anything
/// without the configured key except bootstrap endpoints. Query strings, form
/// values, and content never enter logs because they can hold capability tokens
/// and private library data.
pub(crate) async fn log_and_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string()
    };
    let method = parts.method.clone();
    let path = parts.uri.path().to_owned();
    let log_path = request_log_path(&path).to_owned();
    tracing::info!(
        %method,
        path = %log_path,
        api_version = %header("zotero-api-version"),
        if_unmod = %header("if-unmodified-since-version"),
        "request"
    );
    // These handlers use request parts only. Dispatch before any body polling;
    // Origin, browser binding, claims and CSRF are checked at their boundary.
    if (path == "/xotero/web/session"
        && matches!(method, axum::http::Method::GET | axum::http::Method::POST))
        || (path == "/xotero/web/session/logout" && method == axum::http::Method::POST)
    {
        return next.run(Request::from_parts(parts, body)).await;
    }
    // Admin handlers own the distinct live-session boundary and must see the
    // unpolled body. A data key cannot authorize these routes.
    if path.starts_with("/xotero/admin/") {
        return next.run(Request::from_parts(parts, body)).await;
    }

    let mut selected_access = None;
    let segments: Vec<_> = path.split('/').collect();
    let is_upload = method == axum::http::Method::POST
        && matches!(segments.as_slice(), ["", "uploads", token] if !token.is_empty());
    let is_bootstrap = is_upload
        || (path == "/login"
            && matches!(
                method,
                axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::POST
            ))
        || (path == "/keys/sessions" && method == axum::http::Method::POST)
        || (matches!(segments.as_slice(), ["", "keys", "sessions", token] if !token.is_empty())
            && matches!(
                method,
                axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::DELETE
            ));
    if !is_bootstrap {
        let context = match authenticate_request(&state, &parts.headers).await {
            Ok(Some(context)) => context,
            Ok(None) => return (StatusCode::FORBIDDEN, "invalid API key").into_response(),
            Err(error) => return server_error("API key authentication", error),
        };
        let is_group_discovery = is_group_discovery_path(&path);
        match path_user_id(&path) {
            Ok(Some(path_user_id)) if path_user_id == context.principal.user_id.get() => {}
            Ok(Some(_)) if is_group_discovery => {}
            Ok(Some(_)) => return (StatusCode::FORBIDDEN, "user access denied").into_response(),
            Err(()) => return StatusCode::NOT_FOUND.into_response(),
            Ok(None) => {}
        }
        let group_id = match path_group_data_id(&path) {
            Ok(group_id) => group_id,
            Err(()) => return StatusCode::NOT_FOUND.into_response(),
        };
        let access = if let Some(group_id) = group_id {
            match store::resolve_group_library(
                &state.pool,
                group_id,
                context.principal.user_id,
                context.api_key_id,
                context.api_key_id.is_none().then_some(context.permissions),
            )
            .await
            {
                Ok(store::GroupLibraryResolution::Allowed(access)) => Some(access),
                Ok(store::GroupLibraryResolution::Denied) => {
                    return (StatusCode::FORBIDDEN, "group access denied").into_response();
                }
                Ok(store::GroupLibraryResolution::Missing) => {
                    return StatusCode::NOT_FOUND.into_response();
                }
                Err(error) => return server_error("resolve group library", error),
            }
        } else if path != "/keys/current" && !is_group_discovery {
            if !context.permissions.library {
                return (StatusCode::FORBIDDEN, "library access denied").into_response();
            }
            Some(LibraryAccess {
                library_id: context.principal.library_id,
                group_id: None,
                permissions: context.permissions,
                is_admin: true,
                file_write: context.permissions.write && context.permissions.files,
            })
        } else {
            None
        };
        let is_attachment_path = is_attachment_permission_path(&path);
        if is_attachment_path && access.is_some_and(|access| !access.permissions.files) {
            return (StatusCode::FORBIDDEN, "file access denied").into_response();
        }
        let mutating = matches!(
            parts.method,
            axum::http::Method::POST
                | axum::http::Method::PUT
                | axum::http::Method::PATCH
                | axum::http::Method::DELETE
        );
        if mutating && is_attachment_path && access.is_some_and(|access| !access.file_write) {
            return (StatusCode::FORBIDDEN, "file editing denied").into_response();
        }
        if mutating && access.is_some_and(|access| !access.permissions.write) {
            return (StatusCode::FORBIDDEN, "read-only API key").into_response();
        }
        selected_access = access;
        parts.extensions.insert(context);
    }

    let body = if is_upload {
        body
    } else {
        let limit = if is_bootstrap {
            MAX_PUBLIC_BODY
        } else {
            MAX_BODY
        };
        let bytes = match buffered_body(body, &parts.headers, limit).await {
            Ok(bytes) => bytes,
            Err(status) => return status.into_response(),
        };
        parts.headers.remove("content-encoding");
        parts.headers.remove("content-length");
        Body::from(bytes)
    };
    let request = Request::from_parts(parts, body);
    let response = match selected_access {
        Some(access) => request_access_scope(access, next.run(request)).await,
        None => next.run(request).await,
    };
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        tracing::warn!(
            %method,
            path = %log_path,
            status = status.as_u16(),
            "response error"
        );
    }
    response
}

#[cfg(test)]
mod decoding_tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;
    use tokio::sync::{oneshot, Semaphore};

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn exact_decoded_limit_validates_trailer() {
        let raw = gzip(&[b'x'; 64]);
        assert_eq!(decode_gzip(&raw[..], 64).unwrap().len(), 64);
        assert_eq!(
            decode_gzip(&raw[..], 63),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
        let mut corrupt = raw.clone();
        let trailer = corrupt.len() - 8;
        corrupt[trailer] ^= 1;
        assert_eq!(decode_gzip(&corrupt[..], 64), Err(StatusCode::BAD_REQUEST));
        assert_eq!(
            decode_gzip(&raw[..raw.len() - 1], 64),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn concatenated_members_share_decoded_bound() {
        let mut raw = gzip(b"first");
        raw.extend(gzip(b"second"));
        assert_eq!(decode_gzip(&raw[..], 11).unwrap().as_ref(), b"firstsecond");
        assert_eq!(
            decode_gzip(&raw[..], 10),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
        raw.extend(b"garbage");
        assert_eq!(decode_gzip(&raw[..], 64), Err(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn encoded_limit_distinguishes_boundary_from_overflow() {
        let headers = HeaderMap::new();
        assert_eq!(
            buffered_body(Body::from(vec![b'x'; 64]), &headers, 64)
                .await
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            buffered_body(Body::from(vec![b'x'; 65]), &headers, 64)
                .await
                .unwrap_err(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    struct HeldReader {
        bytes: std::io::Cursor<Vec<u8>>,
        started: Option<oneshot::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl Read for HeldReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if let Some(started) = self.started.take() {
                started.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            self.bytes.read(out)
        }
    }

    #[tokio::test]
    async fn canceled_request_holds_decoder_permit_until_job_exits() {
        // Observers exist before the decoder can start.
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let (started, running) = oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let reader = HeldReader {
            bytes: std::io::Cursor::new(gzip(b"body")),
            started: Some(started),
            release: held,
        };
        let request = tokio::spawn(spawn_decoder(reader, 64, permit));
        tokio::time::timeout(Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        // Cancellation must not free admission while the actual job is held.
        assert!(Arc::clone(&semaphore).try_acquire_owned().is_err());
        release.send(()).unwrap();
        let resumed = tokio::time::timeout(
            Duration::from_secs(3),
            Arc::clone(&semaphore).acquire_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            spawn_decoder(std::io::Cursor::new(gzip(b"resumed")), 64, resumed)
                .await
                .unwrap()
                .as_ref(),
            b"resumed"
        );
    }
}
