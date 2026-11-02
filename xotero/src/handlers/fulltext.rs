use std::collections::HashMap;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};

use crate::error::server_error;
use crate::http::access::{request_access, request_library};
use crate::http::headers::{conflict, precondition, since_of, version_headers};
use crate::{store, AppState};

/// `GET /fulltext?format=versions&since=N` → `{itemKey: version}` for content
/// changed after `since`, so the client downloads only what it lacks.
pub(crate) async fn fulltext_versions(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let since = since_of(&params);
    // Always 200 + map (never 304); see `read` — a 304 here loops the client.
    let current = match store::current_version(&state.pool, request_library()).await {
        Ok(current) => current,
        Err(error) => return server_error("fulltext versions", error),
    };
    match store::fulltext_versions(&state.pool, request_library(), since).await {
        Ok(value) => (version_headers(current), Json(value)).into_response(),
        Err(error) => server_error("fulltext versions", error),
    }
}

/// `GET /items/<key>/fulltext` → the item's content object, with the row's
/// version in `Last-Modified-Version` (the client stores it to skip re-fetching).
pub(crate) async fn fulltext_item(
    State(state): State<AppState>,
    Path((_id, key)): Path<(String, String)>,
) -> Response {
    match store::fulltext_item(&state.pool, request_library(), &key).await {
        Ok(Some((version, data))) => (version_headers(version), Json(data)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error("fulltext item", error),
    }
}

/// `POST /fulltext` — store a batch of extracted content, returning the per-index
/// result map the client reads to mark each item synced (or `412` if stale).
pub(crate) async fn fulltext_write(
    State(state): State<AppState>,
    Extension(context): Extension<crate::domain::RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let batch: Vec<Value> = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(error) => {
            tracing::warn!(%error, "malformed fulltext body");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let expected = match precondition(&headers) {
        Ok(v) => v,
        Err(rejection) => return rejection.into_response(),
    };
    match store::write_fulltext(
        &state.pool,
        store::MutationProof {
            access: request_access(),
            context: &context,
            config: &state.config,
        },
        batch,
        Some(expected),
    )
    .await
    {
        Ok(store::Outcome::Done((version, successful))) => (
            version_headers(version),
            Json(json!({
                "successful": successful,
                "success": {},
                "unchanged": {},
                "failed": {},
            })),
        )
            .into_response(),
        Ok(store::Outcome::Conflict(current)) => conflict(current),
        Ok(store::Outcome::Denied) => StatusCode::FORBIDDEN.into_response(),
        Err(error) => server_error("fulltext write", error),
    }
}
