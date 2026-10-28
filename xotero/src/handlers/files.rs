use std::collections::HashMap;

use axum::{
    extract::{Form, Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::domain::{LibraryId, RequestContext};
use crate::error::{s3_error, server_error};
use crate::http::access::{request_access, request_library};
use crate::http::headers::{conflict, current_headers, header_value, version_headers};
use crate::http::validation::valid_key;
use crate::{store, upload_token, AppState};

fn upload_storage_key(library_id: LibraryId, upload_token: &str) -> String {
    format!("libraries/{}/uploads/{upload_token}", library_id.get())
}

fn key_hash(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

/// Attachment file endpoint. The same path serves both POST steps:
/// authorisation (`md5`/`filename`/`filesize`/`mtime` form) and registration
/// (`upload` form, after the bytes have been PUT to the upload URL).
pub(crate) async fn file_post(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path((_id, key)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !valid_key(&key) {
        return (StatusCode::BAD_REQUEST, "invalid item key").into_response();
    }
    // Registration step: the client posts upload=<token> after PUTting the bytes
    // to the upload endpoint, which verified them and stored the object.
    if let Some(token) = form.get("upload") {
        let token_hash = key_hash(token);
        let upload = match store::pending_upload(&state.pool, &token_hash).await {
            Ok(Some(upload)) => upload,
            Ok(None) => {
                return (StatusCode::BAD_REQUEST, "no pending upload").into_response();
            }
            Err(error) => return server_error("pending upload lookup", error),
        };
        if upload.item_key != key {
            return (StatusCode::BAD_REQUEST, "upload token does not match item").into_response();
        }
        if upload.library_id != request_library() {
            return (StatusCode::FORBIDDEN, "upload token library mismatch").into_response();
        }
        if upload.group_id != request_access().group_id {
            return (StatusCode::FORBIDDEN, "upload token group mismatch").into_response();
        }
        if upload.state != store::PendingUploadState::Uploaded {
            return (StatusCode::BAD_REQUEST, "no uploaded bytes").into_response();
        }
        let outcome = store::register_file(
            &state.pool,
            &token_hash,
            &key,
            request_access(),
            &context,
            &state.config,
        )
        .await;
        return match outcome {
            Ok(store::FileRegistrationOutcome::Done(version)) => {
                (StatusCode::NO_CONTENT, version_headers(version)).into_response()
            }
            Ok(store::FileRegistrationOutcome::Conflict(current)) => {
                cleanup_pending_uploads(&state).await;
                conflict(current)
            }
            Ok(store::FileRegistrationOutcome::InvalidItem) => {
                cleanup_pending_uploads(&state).await;
                (StatusCode::CONFLICT, "attachment item changed").into_response()
            }
            Ok(store::FileRegistrationOutcome::InvalidUpload) => {
                (StatusCode::BAD_REQUEST, "no pending upload").into_response()
            }
            Ok(store::FileRegistrationOutcome::Denied) => {
                (StatusCode::FORBIDDEN, "upload access revoked").into_response()
            }
            Err(error) => server_error("register file", error),
        };
    }

    // Authorization step. The client sends a precondition: `If-None-Match: *`
    // for a new file, or `If-Match: <oldmd5>` to replace an existing one. Without
    // either, the version guard would be bypassed (428, as zfs.js expects).
    let if_none_match = headers.contains_key("if-none-match");
    let if_match = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    if !if_none_match && if_match.is_none() {
        return (
            StatusCode::PRECONDITION_REQUIRED,
            "If-Match or If-None-Match required",
        )
            .into_response();
    }
    match store::stored_file_attachment_exists(&state.pool, request_library(), &key).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error("file attachment lookup", error),
    }

    let md5 = form.get("md5").cloned().unwrap_or_default();
    let stored_md5 = match store::file_meta(&state.pool, request_library(), &key).await {
        Ok(meta) => meta.map(|meta| meta.md5),
        Err(error) => return server_error("file auth", error),
    };
    let zip_md5 = form.get("zipMD5").filter(|value| !value.is_empty());
    let zip_filename = form.get("zipFilename").filter(|value| !value.is_empty());
    if zip_md5.is_some() != zip_filename.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            "zipMD5 and zipFilename must be provided together",
        )
            .into_response();
    }
    let compressed = zip_md5.is_some()
        || form
            .get("zip")
            .is_some_and(|value| !value.is_empty() && value != "0");
    let upload_md5 = zip_md5.cloned().unwrap_or_else(|| md5.clone());

    // md5 hex compares case-insensitively, matching the verification in
    // upload_put (which lowercases) so dedup and replace agree on normalization.
    if if_none_match {
        // "Only if no file exists." Same md5 → already uploaded (dedup); a
        // different existing file → conflict.
        if let Some(existing) = &stored_md5 {
            if existing.eq_ignore_ascii_case(&md5) {
                return match current_headers(&state).await {
                    Ok(headers) => (headers, Json(json!({ "exists": 1 }))).into_response(),
                    Err(error) => server_error("file authorization version", error),
                };
            }
            return match store::current_version(&state.pool, request_library()).await {
                Ok(current) => conflict(current),
                Err(error) => server_error("file authorization version", error),
            };
        }
    } else if let Some(want) = &if_match {
        // "Only if the current md5 matches." Otherwise → conflict.
        if !stored_md5
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case(want))
        {
            return match store::current_version(&state.pool, request_library()).await {
                Ok(current) => conflict(current),
                Err(error) => server_error("file authorization version", error),
            };
        }
    }

    // Authorize: persist only the capability digest. Candidate bytes use a
    // separate random object ID so the database never stores the raw token.
    cleanup_pending_uploads(&state).await;
    let Some(token) = upload_token() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Some(candidate_id) = upload_token() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let upload = store::PendingUpload {
        library_id: request_library(),
        group_id: request_access().group_id,
        authorizer_key_hash: key_hash(&context.presented_key),
        bootstrap_user_id: context
            .api_key_id
            .is_none()
            .then_some(context.principal.user_id),
        item_key: key.clone(),
        expected_md5: if if_none_match {
            None
        } else {
            stored_md5.clone()
        },
        blob_key: upload_storage_key(request_library(), &candidate_id),
        md5,
        upload_md5,
        filename: form.get("filename").cloned().unwrap_or_default(),
        filesize: form
            .get("filesize")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        mtime: form.get("mtime").and_then(|s| s.parse().ok()).unwrap_or(0),
        compressed,
        state: store::PendingUploadState::Authorized,
    };
    if let Err(error) = store::create_pending_upload(&state.pool, &key_hash(&token), &upload).await
    {
        return server_error("create pending upload", error);
    }
    // Empty prefix/suffix: the client PUTs the raw file bytes to url.
    Json(json!({
        "url": format!("{}/uploads/{}", state.config.public_url, token),
        "uploadKey": token,
        "contentType": if compressed { "application/zip" } else { "application/octet-stream" },
        "prefix": "",
        "suffix": "",
    }))
    .into_response()
}

pub(crate) async fn cleanup_pending_uploads(state: &AppState) {
    let cutoff = match store::pending_upload_cleanup_cutoff(&state.pool).await {
        Ok(cutoff) => cutoff,
        Err(error) => {
            tracing::warn!(%error, "start pending upload cleanup");
            return;
        }
    };
    loop {
        let garbage = match store::claim_pending_upload_garbage(&state.pool, 32, &cutoff).await {
            Ok(garbage) => garbage,
            Err(error) => {
                tracing::warn!(%error, "claim pending upload garbage");
                return;
            }
        };
        if garbage.is_empty() {
            return;
        }
        for candidate in garbage {
            match tokio::time::timeout(
                state.config.upload_timeout,
                state.storage.delete(&candidate.blob_key),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, "delete pending upload candidate");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "pending upload cleanup deadline");
                    continue;
                }
            }
            if let Err(error) =
                store::delete_pending_upload_garbage(&state.pool, &candidate.token_hash).await
            {
                tracing::warn!(%error, "finish pending upload cleanup");
            }
        }
    }
}

pub(crate) async fn pending_upload_cleanup_loop(state: AppState) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        cleanup_pending_uploads(&state).await;
    }
}

/// One finite due-work pass. The durable claim outlives this process and every
/// remote failure; only an acknowledged claim COMMIT authorizes deletion.
pub(crate) async fn cleanup_retired_blobs(
    pool: &sqlx::PgPool,
    storage: &crate::s3::Storage,
    timeout: std::time::Duration,
) -> sqlx::Result<bool> {
    let cutoff = store::pending_upload_cleanup_cutoff(pool).await?;
    let mut after = String::new();
    let mut complete = true;
    loop {
        let keys = store::due_blob_keys(pool, &cutoff, &after).await?;
        if keys.is_empty() {
            return Ok(complete);
        }
        for key in keys {
            after.clone_from(&key);
            let Some(claim) = store::claim_retired_blob(pool, &key).await? else {
                continue;
            };
            // No transaction or blob lock spans the S3 operation. A concurrent
            // publisher sees Claimed, including throughout deletion retries.
            match tokio::time::timeout(timeout, storage.delete(&claim.blob_key)).await {
                Ok(Ok(())) => store::finish_retired_blob(pool, claim).await?,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "retired blob deletion will retry");
                    complete = false;
                }
                Err(error) => {
                    tracing::warn!(%error, "retired blob deletion deadline");
                    complete = false;
                }
            }
        }
    }
}

/// Receive the raw attachment bytes for a pending upload token, verify them
/// against the authorized md5/filesize, and store an immutable candidate.
/// Rejects an unknown token. Verifying here (where the bytes are in hand) keeps
/// the integrity check server-side now that the bytes go straight to S3.
pub(crate) async fn upload_put(
    State(state): State<AppState>,
    Path(token): Path<String>,
    request: Request,
) -> Response {
    let deadline = tokio::time::Instant::now() + state.config.upload_timeout;
    match tokio::time::timeout_at(deadline, receive_upload(state, token, request, deadline)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

async fn receive_upload(
    state: AppState,
    token: String,
    request: Request,
    deadline: tokio::time::Instant,
) -> Response {
    let (parts, body) = request.into_parts();
    let (body, body_polls) = crate::upload::observed_body(body);
    let token_hash = key_hash(&token);
    let upload = match store::pending_upload(&state.pool, &token_hash).await {
        Ok(Some(upload)) => upload,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, "unknown upload token").into_response();
        }
        Err(error) => return server_error("pending upload lookup", error),
    };
    if upload.state != store::PendingUploadState::Authorized {
        return (StatusCode::CONFLICT, "upload token already used").into_response();
    }
    match upload.authorized(&state.pool, &state.config).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::FORBIDDEN, "upload access revoked").into_response(),
        Err(error) => return server_error("upload authorization", error),
    }
    let size = match u64::try_from(upload.filesize) {
        Ok(size) if size <= state.config.upload_max_bytes => size,
        _ => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    // Admission owns no application bytes. Queuing is included in total deadline.
    let permit = match tokio::time::timeout_at(
        deadline,
        crate::upload::admit(state.uploads.clone(), &body_polls),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(error)) => {
            tracing::error!(%error, "upload admission");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
    };
    let mut reader = match crate::upload::attachment_reader(
        body,
        &parts.headers,
        state.config.upload_max_bytes,
        size,
        upload.upload_md5.clone(),
    ) {
        Ok(reader) => reader,
        Err(status) => return status.into_response(),
    };
    let (mut reply, response) = tokio::sync::oneshot::channel();
    // The supervisor survives a dropped HTTP future. It finishes the durable
    // claim before observing cancellation, then drops SDK work before cleanup.
    tokio::spawn(async move {
        let _permit = permit;
        let response = match store::claim_pending_upload(&state.pool, &token_hash).await {
            Ok(true) => {
                let content_type = if upload.compressed {
                    "application/zip"
                } else {
                    "application/octet-stream"
                };
                let transfer = tokio::select! {
                    biased;
                    _ = reply.closed() => Err(StatusCode::BAD_REQUEST.into_response()),
                    result = tokio::time::timeout_at(
                        deadline,
                        state.storage.put(
                            &upload.blob_key,
                            &mut reader,
                            content_type,
                            state.config.upload_parts,
                        ),
                    ) => match result {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(error)) => Err(match reader.error {
                            Some(status) => status.into_response(),
                            None => s3_error("store file", error),
                        }),
                        Err(_) => Err(StatusCode::REQUEST_TIMEOUT.into_response()),
                    }
                };
                match transfer {
                    Ok(()) => {
                        match store::mark_pending_upload_uploaded(
                            &state.pool,
                            &token_hash,
                            deadline,
                            reply.closed(),
                        )
                        .await
                        {
                            Ok(true) => StatusCode::CREATED.into_response(),
                            Ok(false) => {
                                discard_upload(&state, &token_hash, false).await;
                                StatusCode::CONFLICT.into_response()
                            }
                            // Unknown acknowledgement must never cause object deletion.
                            Err(error) => server_error("complete pending upload", error),
                        }
                    }
                    Err(response) => {
                        // Before the first SDK chunk is full, a reader error
                        // precedes any network request. Preserve small-file retries.
                        if reader.error.is_some() && reader.bytes < 8 * 1024 * 1024 {
                            if let Err(error) =
                                store::reset_pending_upload(&state.pool, &token_hash).await
                            {
                                tracing::warn!(%error, "reset unstarted upload");
                            }
                        } else {
                            discard_upload(&state, &token_hash, true).await;
                        }
                        response
                    }
                }
            }
            Ok(false) => StatusCode::CONFLICT.into_response(),
            Err(error) => {
                // A failed claim does not prove ownership. Another contender
                // may already own Uploading; startup resolves unknown claims.
                server_error("claim pending upload", error)
            }
        };
        if reply.send(response).is_err() {
            tracing::debug!("upload requester disconnected");
        }
    });
    response.await.unwrap_or_else(|error| {
        tracing::error!(%error, "upload supervisor");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })
}

async fn discard_upload(state: &AppState, token_hash: &[u8], uncertain: bool) {
    if let Err(error) = store::discard_pending_upload(&state.pool, token_hash, uncertain).await {
        tracing::warn!(%error, "discard failed upload");
        return;
    }
    cleanup_pending_uploads(state).await;
}

/// The client reads md5/mtime from this response's headers and then downloads
/// the bytes from `Location` — a short-lived pre-signed GET URL pointing straight
/// at the bucket, so the read path bypasses this server entirely (and the URL is
/// an unguessable, expiring capability the client follows without an API key).
pub(crate) async fn file_get(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path((_id, key)): Path<(String, String)>,
) -> Response {
    if !valid_key(&key) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return server_error("begin file signing", error),
    };
    let meta =
        match store::file_for_signing(&mut tx, &key, request_access(), &context, &state.config)
            .await
        {
            Ok(store::FileSigningOutcome::Allowed(meta)) => meta,
            Ok(store::FileSigningOutcome::Missing) => return StatusCode::NOT_FOUND.into_response(),
            Ok(store::FileSigningOutcome::Denied) => return StatusCode::FORBIDDEN.into_response(),
            Err(error) => return server_error("authorize file signing", error),
        };
    if let Err(error) = store::record_presign_ttl(&mut tx, state.storage.presign_ttl()).await {
        return server_error("record file signing lifetime", error);
    }
    let url = match state.storage.presign_get(&meta.blob_key).await {
        Ok(url) => url,
        Err(error) => return s3_error("presign download", error),
    };
    // The library shared lock protects actual signing, not just URL metadata
    // lookup. An unknown COMMIT outcome must not release this URL to the client.
    if let Err(error) = tx.commit().await {
        return server_error("commit file signing lifetime", error);
    }
    let mut headers = HeaderMap::new();
    headers.insert("location", header_value(&url));
    headers.insert(
        "zotero-file-modification-time",
        header_value(&meta.mtime.to_string()),
    );
    headers.insert("zotero-file-md5", header_value(&meta.blob_md5));
    headers.insert("zotero-file-size", header_value(&meta.filesize.to_string()));
    headers.insert(
        "zotero-file-compressed",
        header_value(if meta.compressed { "Yes" } else { "No" }),
    );
    (StatusCode::FOUND, headers).into_response()
}
