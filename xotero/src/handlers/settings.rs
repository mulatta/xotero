use std::collections::HashMap;

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};

use crate::error::server_error;
use crate::http::access::{request_access, request_library};
use crate::http::headers::{
    conflict, csv_of, current_headers, if_modified_since, precondition, since_check, since_of,
    version_headers,
};
use crate::{store, AppState};

pub(crate) async fn settings_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // The client may send the cursor as ?since= or the If-Modified-Since-Version
    // header; honour whichever is higher.
    let since = since_of(&params).max(if_modified_since(&headers));
    let (current, fresh) = match since_check(&state, since).await {
        Ok(result) => result,
        Err(error) => return server_error("settings version", error),
    };
    if fresh {
        return (StatusCode::NOT_MODIFIED, version_headers(current)).into_response();
    }
    match store::settings(&state.pool, request_library()).await {
        Ok(value) => (version_headers(current), Json(value)).into_response(),
        Err(error) => server_error("settings", error),
    }
}

pub(crate) async fn settings_write(
    State(state): State<AppState>,
    Extension(context): Extension<crate::domain::RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let expected = match precondition(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let value: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    match store::write_settings(
        &state.pool,
        store::MutationProof {
            access: request_access(),
            context: &context,
            config: &state.config,
        },
        value,
        Some(expected),
    )
    .await
    {
        Ok(store::Outcome::Done(version)) => {
            (StatusCode::NO_CONTENT, version_headers(version)).into_response()
        }
        Ok(store::Outcome::Conflict(current)) => conflict(current),
        Ok(store::Outcome::Denied) => StatusCode::FORBIDDEN.into_response(),
        Err(error) => server_error("settings write", error),
    }
}

/// `DELETE /settings?settingKey=k1,k2` — remove the named settings under the
/// version guard and record them in the deletion log. (Reusing settings_write
/// here was a no-op: a DELETE has no body, so it deleted nothing yet returned
/// 204 and the setting persisted.)
pub(crate) async fn settings_delete(
    State(state): State<AppState>,
    Extension(context): Extension<crate::domain::RequestContext>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let expected = match precondition(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let keys = csv_of(&params, "settingKey");
    match store::delete_settings(
        &state.pool,
        store::MutationProof {
            access: request_access(),
            context: &context,
            config: &state.config,
        },
        &keys,
        Some(expected),
    )
    .await
    {
        Ok(store::Outcome::Done(version)) => {
            (StatusCode::NO_CONTENT, version_headers(version)).into_response()
        }
        Ok(store::Outcome::Conflict(current)) => conflict(current),
        Ok(store::Outcome::Denied) => StatusCode::FORBIDDEN.into_response(),
        Err(error) => server_error("settings delete", error),
    }
}

pub(crate) async fn deleted(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let since = since_of(&params);
    match store::deleted(&state.pool, request_library(), since).await {
        Ok(value) => match current_headers(&state).await {
            Ok(headers) => (headers, Json(value)).into_response(),
            Err(error) => server_error("deleted version", error),
        },
        Err(error) => server_error("deleted", error),
    }
}
