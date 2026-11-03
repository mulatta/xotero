use std::collections::HashMap;

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{http::access::request_library, store, AppState};

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

/// Upstream `buildLinks`/`buildLinkHeader` for a listing page at `base` (the
/// public URL plus path). `params` are the sorted non-default parameters
/// without `start`. `alternate` is never emitted: it names the zotero.org
/// website, which xotero does not have. `None` when no link applies.
pub(crate) fn link_header(
    base: &str,
    params: &[(String, String)],
    start: i64,
    limit: i64,
    total: i64,
) -> Option<String> {
    // Upstream drops a non-positive start from every link URL.
    let url = |start: i64| {
        let mut pairs = params.to_vec();
        if start > 0 {
            pairs.push(("start".into(), start.to_string()));
            pairs.sort();
        }
        if pairs.is_empty() {
            return base.to_string();
        }
        format!(
            "{base}?{}",
            serde_urlencoded::to_string(&pairs).unwrap_or_default()
        )
    };
    let this = url(start);
    let mut parts = Vec::new();
    let first = url(0);
    if first != this {
        parts.push(format!("<{first}>; rel=\"first\""));
    }
    if start > 0 {
        parts.push(format!("<{}>; rel=\"prev\"", url(start - limit)));
    }
    if (start > 0 || limit < total) && limit != 0 {
        if start + limit < total {
            parts.push(format!("<{}>; rel=\"next\"", url(start + limit)));
        }
        let last_start = if start >= total || total % limit == 0 {
            total - limit
        } else {
            total - total % limit
        };
        let last = url(last_start);
        if last != this {
            parts.push(format!("<{last}>; rel=\"last\""));
        }
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "B/users/101/items";

    fn params(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn link_first_page_has_next_and_last() {
        assert_eq!(
            link_header(BASE, &params(&[("sort", "title")]), 0, 25, 28).as_deref(),
            Some("<B/users/101/items?sort=title&start=25>; rel=\"next\", <B/users/101/items?sort=title&start=25>; rel=\"last\"")
        );
        assert_eq!(
            link_header(BASE, &params(&[("format", "keys"), ("limit", "25"), ("sort", "title")]), 0, 25, 28).as_deref(),
            Some("<B/users/101/items?format=keys&limit=25&sort=title&start=25>; rel=\"next\", <B/users/101/items?format=keys&limit=25&sort=title&start=25>; rel=\"last\"")
        );
    }

    #[test]
    fn link_last_page_has_first_and_prev() {
        assert_eq!(
            link_header(BASE, &params(&[("sort", "date")]), 25, 25, 28).as_deref(),
            Some("<B/users/101/items?sort=date>; rel=\"first\", <B/users/101/items?sort=date>; rel=\"prev\"")
        );
    }

    #[test]
    fn link_single_page_and_unlimited_are_empty() {
        assert_eq!(link_header(BASE, &[], 0, 25, 3), None);
        assert_eq!(link_header(BASE, &[], 0, 0, 28), None);
        assert_eq!(link_header(BASE, &[], 0, 25, 0), None);
    }

    #[test]
    fn link_edge_cases() {
        // An exact multiple of the limit: the last page starts one limit back.
        assert_eq!(
            link_header(BASE, &[], 0, 25, 50).as_deref(),
            Some("<B/users/101/items?start=25>; rel=\"next\", <B/users/101/items?start=25>; rel=\"last\"")
        );
        // Start past the end: last is total - limit, no next.
        assert_eq!(
            link_header(BASE, &[], 100, 25, 28).as_deref(),
            Some("<B/users/101/items>; rel=\"first\", <B/users/101/items?start=75>; rel=\"prev\", <B/users/101/items?start=3>; rel=\"last\"")
        );
        // limit 0 past the first row: only first and prev.
        assert_eq!(
            link_header(BASE, &[], 10, 0, 28).as_deref(),
            Some("<B/users/101/items>; rel=\"first\", <B/users/101/items?start=10>; rel=\"prev\"")
        );
        // start lands between keys alphabetically; spaces encode as `+`.
        assert_eq!(
            link_header(BASE, &params(&[("q", "a b"), ("tag", "x")]), 0, 1, 2).as_deref(),
            Some("<B/users/101/items?q=a+b&start=1&tag=x>; rel=\"next\", <B/users/101/items?q=a+b&start=1&tag=x>; rel=\"last\"")
        );
    }
}
