use std::collections::HashMap;

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{http::access::request_library, store, AppState, Config};

pub(crate) fn version_headers(version: i64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "last-modified-version",
        version.to_string().parse().unwrap(),
    );
    headers
}

pub(crate) async fn current_headers(state: &AppState) -> sqlx::Result<HeaderMap> {
    Ok(version_headers(
        store::current_version(&state.pool, request_library()).await?,
    ))
}

/// For a since/versions read: the current library version, and whether the
/// client already holds everything up to it (→ `304 Not Modified`; nothing has a
/// version greater than `since`). `since == 0` is the initial pull, so never
/// 304 it. One DB read, so the caller reuses `current` for the response's
/// `Last-Modified-Version` instead of querying it again.
pub(crate) async fn since_check(state: &AppState, since: i64) -> sqlx::Result<(i64, bool)> {
    let current = store::current_version(&state.pool, request_library()).await?;
    Ok((current, since > 0 && since >= current))
}

/// The `If-Modified-Since-Version` request header (0 if absent/unparseable). The
/// client uses it on reads that don't carry a `since` query param (e.g. settings).
pub(crate) fn if_modified_since(headers: &HeaderMap) -> i64 {
    headers
        .get("if-modified-since-version")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Build a header value from stored/derived text without panicking on a stray
/// byte (e.g. a malformed md5); an invalid value is dropped rather than 500ing.
pub(crate) fn header_value(text: &str) -> axum::http::HeaderValue {
    text.parse()
        .unwrap_or_else(|_| axum::http::HeaderValue::from_static(""))
}

/// The library version the client expects to still hold; a mismatch is a 412.
pub(crate) fn if_unmodified(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("if-unmodified-since-version")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

/// A mutating data write must carry a parseable `If-Unmodified-Since-Version`.
/// Without it the version guard is bypassed (a missing/garbage header would let
/// the write commit unconditionally), so reject it with `428 Precondition
/// Required` — the same contract the file endpoints use.
pub(crate) fn precondition(headers: &HeaderMap) -> Result<i64, PreconditionRequired> {
    if_unmodified(headers).ok_or(PreconditionRequired)
}

/// Rejection for a mutating write without a usable version precondition.
pub(crate) struct PreconditionRequired;

impl IntoResponse for PreconditionRequired {
    fn into_response(self) -> Response {
        (
            StatusCode::PRECONDITION_REQUIRED,
            "If-Unmodified-Since-Version required",
        )
            .into_response()
    }
}

pub(crate) fn conflict(current: i64) -> Response {
    (StatusCode::PRECONDITION_FAILED, version_headers(current)).into_response()
}

/// The `since` read cursor (defaults to 0, the initial pull).
pub(crate) fn since_of(params: &HashMap<String, String>) -> i64 {
    params
        .get("since")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Zotero CSV query params (`itemKey=A,B`, `tag=x,y`) with empty parts ignored.
pub(crate) fn csv_of(params: &HashMap<String, String>, key: &str) -> Vec<String> {
    params
        .get(key)
        .map(|s| {
            s.split(',')
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The `Link: <…>; rel="next"` header for the page after `start`, preserving the
/// request's other params and pointing at the public (reverse-proxy) URL.
pub(crate) fn next_link(config: &Config, path: &str, raw: Option<&str>, start: i64) -> String {
    let mut pairs: Vec<(String, String)> = raw
        .and_then(|q| serde_urlencoded::from_str(q).ok())
        .unwrap_or_default();
    pairs.retain(|(k, _)| k != "start");
    pairs.push(("start".into(), start.to_string()));
    let qs = serde_urlencoded::to_string(&pairs).unwrap_or_default();
    format!("<{}{}?{}>; rel=\"next\"", config.public_url, path, qs)
}
