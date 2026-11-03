use std::collections::HashMap;

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, RawQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::error::{server_error, unsupported};
use crate::http::access::{request_access, request_library, request_permissions};
use crate::http::headers::{
    conflict, csv_of, current_headers, header_value, link_header, precondition, version_headers,
};
use crate::http::validation::valid_object_key;
use crate::{query, store, AppState};

/// `format=versions&since=N` returns the changed `{key: version}` map; otherwise
/// `?<kind>Key=a,b&format=json` returns the full `[{key, version, data}]`.
pub(crate) async fn read(
    state: &AppState,
    kind: &str,
    params: HashMap<String, String>,
    raw: Option<&str>,
) -> Response {
    let list_kind = match kind {
        "collection" => query::ListKind::Collections,
        _ => query::ListKind::Searches,
    };
    let listing = match query::Listing::parse(&query::Params::parse(raw), list_kind) {
        Ok(listing) => listing,
        Err(query::Unsupported) => return reject(state).await,
    };
    if listing.format == query::Format::Versions {
        let since = listing.since.unwrap_or(0);
        // Always 200 with the (possibly empty) versions map. The client's
        // `getVersions` sends no `If-Modified-Since-Version` header and treats a
        // 304 as "no data", which then mismatches its library-version check and
        // makes it restart the sync forever. 304 is only for the header path
        // (settings), not for `?since=` versions reads.
        let current = match store::current_version(&state.pool, request_library()).await {
            Ok(current) => current,
            Err(error) => return server_error("read version", error),
        };
        return match store::versions(&state.pool, request_library(), kind, since, true).await {
            Ok(value) => (version_headers(current), Json(value)).into_response(),
            Err(error) => server_error("read", error),
        };
    }
    let keys = csv_of(&params, &format!("{kind}Key"));
    match store::objects(&state.pool, request_library(), kind, &keys, true).await {
        Ok(value) => match current_headers(state).await {
            Ok(headers) => (headers, Json(value)).into_response(),
            Err(error) => server_error("read version", error),
        },
        Err(error) => server_error("read", error),
    }
}

/// 400 for a listing request that `query` rejected.
async fn reject(state: &AppState) -> Response {
    match current_headers(state).await {
        Ok(headers) => unsupported(headers),
        Err(error) => server_error("unsupported version", error),
    }
}

/// The `?itemKey=…` batch read the sync client sends to `/items` and
/// `/items/top`. Returns `None` for any other request.
async fn item_batch_read(
    state: &AppState,
    params: &query::Params,
    q: &query::ItemQuery,
) -> Option<Response> {
    let csv = params.get("itemKey")?;
    if q.listing.format != query::Format::Json {
        return None;
    }
    let keys: Vec<String> = csv.split(',').map(String::from).collect();
    Some(
        match store::objects(
            &state.pool,
            request_library(),
            "item",
            &keys,
            request_permissions().notes,
        )
        .await
        {
            Ok(value) => match current_headers(state).await {
                Ok(headers) => (headers, Json(value)).into_response(),
                Err(error) => server_error("items batch version", error),
            },
            Err(error) => server_error("items batch", error),
        },
    )
}

/// Answer an item listing in its format, always with `Total-Results` and, when
/// a page link applies, `Link` built against `path` (the public-URL endpoint).
/// versions is always 200 + map, never 304: the client's `getVersions` treats a
/// 304 as "no data" and restarts the sync forever.
async fn item_listing(
    state: &AppState,
    path: &str,
    params: &query::Params,
    q: &query::ItemQuery,
) -> Response {
    let (items, total) = match store::query_items(
        &state.pool,
        request_library(),
        q,
        request_permissions().notes,
    )
    .await
    {
        Ok(page) => page,
        Err(error) => return server_error("items query", error),
    };
    let mut headers = match current_headers(state).await {
        Ok(headers) => headers,
        Err(error) => return server_error("items query version", error),
    };
    headers.insert("total-results", header_value(&total.to_string()));
    let base = format!("{}{}", state.config.public_url, path);
    let link_params = q.listing.link_params(params);
    if let Some(link) = link_header(&base, &link_params, q.listing.start, q.listing.limit, total) {
        headers.insert("link", header_value(&link));
    }
    match q.listing.format {
        query::Format::Json => {
            let items: Vec<Value> = items
                .into_iter()
                .map(|item| json!({"key": item.key, "version": item.version, "data": item.data}))
                .collect();
            (headers, Json(items)).into_response()
        }
        // Zotero's `getKeys()` splits the body on '\n'; upstream ends it with one.
        query::Format::Keys => {
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/plain"),
            );
            let mut body: String = items
                .iter()
                .map(|item| item.key.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            body.push('\n');
            (headers, body).into_response()
        }
        query::Format::Versions => {
            let map: serde_json::Map<String, Value> = items
                .into_iter()
                .map(|item| (item.key, Value::from(item.version)))
                .collect();
            (headers, Json(Value::Object(map))).into_response()
        }
    }
}

/// `GET /users/<id>/items`: the `itemKey` batch read, or the listing.
pub(crate) async fn items_get(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    RawQuery(raw): RawQuery,
) -> Response {
    let params = query::Params::parse(raw.as_deref());
    let q = match query::ItemQuery::from_params(&params) {
        Ok(q) => q,
        Err(query::Unsupported) => return reject(&state).await,
    };
    if let Some(resp) = item_batch_read(&state, &params, &q).await {
        return resp;
    }
    item_listing(&state, uri.path(), &params, &q).await
}

/// `GET /users/<id>/items/top`: top-level items (no `parentItem`). Also answers
/// the sync `itemKey` batch read sent here.
pub(crate) async fn items_top(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    RawQuery(raw): RawQuery,
) -> Response {
    let params = query::Params::parse(raw.as_deref());
    let mut q = match query::ItemQuery::from_params(&params) {
        Ok(q) => q,
        Err(query::Unsupported) => return reject(&state).await,
    };
    if let Some(resp) = item_batch_read(&state, &params, &q).await {
        return resp;
    }
    q.top = true;
    item_listing(&state, uri.path(), &params, &q).await
}

/// `GET /users/<id>/items/trash`: only trashed items (`data.deleted`).
pub(crate) async fn items_trash(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    RawQuery(raw): RawQuery,
) -> Response {
    let params = query::Params::parse(raw.as_deref());
    let mut q = match query::ItemQuery::from_params(&params) {
        Ok(q) => q,
        Err(query::Unsupported) => return reject(&state).await,
    };
    q.only_trashed = true;
    item_listing(&state, uri.path(), &params, &q).await
}

/// `GET /users/<id>/collections/<key>/items`: items in the given collection.
pub(crate) async fn collection_items(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path((_id, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> Response {
    let params = query::Params::parse(raw.as_deref());
    let mut q = match query::ItemQuery::from_params(&params) {
        Ok(q) => q,
        Err(query::Unsupported) => return reject(&state).await,
    };
    q.collection = Some(key);
    item_listing(&state, uri.path(), &params, &q).await
}

/// `GET /users/<id>/collections/<key>/items/top`: top-level items in the
/// collection. The sync client requests this with `format=keys` when restoring a
/// previously-deleted collection (syncEngine.js `_restoreRestoredCollectionItems`).
pub(crate) async fn collection_items_top(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path((_id, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> Response {
    let params = query::Params::parse(raw.as_deref());
    let mut q = match query::ItemQuery::from_params(&params) {
        Ok(q) => q,
        Err(query::Unsupported) => return reject(&state).await,
    };
    q.collection = Some(key);
    q.top = true;
    item_listing(&state, uri.path(), &params, &q).await
}

/// Both POST and PATCH create-or-update with merge semantics (see `store::write`):
/// the Zotero client uploads only an existing object's changed fields, so omitted
/// fields must be preserved.
pub(crate) async fn write(
    state: &AppState,
    context: &crate::domain::RequestContext,
    kind: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let batch: Vec<Value> = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(error) => {
            tracing::warn!(%error, "malformed write body");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    // Reject a malformed object key up front (a keyless object is fine — the
    // store assigns one). A bad key would otherwise sync and the client would
    // refuse it with "key is not valid".
    if let Some(bad) = batch
        .iter()
        .filter_map(|o| o.get("key").and_then(Value::as_str))
        .find(|k| !valid_object_key(k))
    {
        return (
            StatusCode::BAD_REQUEST,
            format!("invalid object key: {bad}"),
        )
            .into_response();
    }
    let expected = match precondition(&headers) {
        Ok(v) => v,
        Err(rejection) => return rejection.into_response(),
    };
    let access = request_access();
    match store::write(
        &state.pool,
        store::MutationProof {
            access,
            context,
            config: &state.config,
        },
        kind,
        batch,
        Some(expected),
    )
    .await
    {
        Ok(store::ObjectMutation::Done((version, successful))) => (
            version_headers(version),
            Json(json!({
                "successful": successful,
                "success": {},
                "unchanged": {},
                "failed": {},
            })),
        )
            .into_response(),
        Ok(store::ObjectMutation::Conflict(current)) => conflict(current),
        Ok(store::ObjectMutation::Denied) => StatusCode::FORBIDDEN.into_response(),
        Ok(store::ObjectMutation::FileWriteDenied) => {
            (StatusCode::FORBIDDEN, "group file editing denied").into_response()
        }
        Err(error) => server_error("write", error),
    }
}

pub(crate) async fn delete(
    state: &AppState,
    context: &crate::domain::RequestContext,
    kind: &str,
    headers: HeaderMap,
    params: HashMap<String, String>,
) -> Response {
    let expected = match precondition(&headers) {
        Ok(v) => v,
        Err(rejection) => return rejection.into_response(),
    };
    let keys = csv_of(&params, &format!("{kind}Key"));
    let access = request_access();
    match store::delete(
        &state.pool,
        store::MutationProof {
            access,
            context,
            config: &state.config,
        },
        kind,
        &keys,
        Some(expected),
    )
    .await
    {
        Ok(store::ObjectMutation::Done(version)) => {
            (StatusCode::NO_CONTENT, version_headers(version)).into_response()
        }
        Ok(store::ObjectMutation::Conflict(current)) => conflict(current),
        Ok(store::ObjectMutation::Denied) => StatusCode::FORBIDDEN.into_response(),
        Ok(store::ObjectMutation::FileWriteDenied) => {
            (StatusCode::FORBIDDEN, "group file editing denied").into_response()
        }
        Err(error) => server_error("delete", error),
    }
}
