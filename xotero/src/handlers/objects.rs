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
use crate::metadata::SCHEMA;
use crate::{envelope, query, store, AppState};

/// `GET /collections` and `/searches`: the `?<kind>Key=a,b` batch read the sync
/// client sends with format json, or the listing.
pub(crate) async fn read(
    state: &AppState,
    kind: &str,
    params: HashMap<String, String>,
    raw: Option<&str>,
    path: &str,
) -> Response {
    let list_kind = match kind {
        "collection" => query::ListKind::Collections,
        _ => query::ListKind::Searches,
    };
    let query_params = query::Params::parse(raw);
    let listing = match query::Listing::parse(&query_params, list_kind) {
        Ok(listing) => listing,
        Err(query::Unsupported) => return reject(state).await,
    };
    let keys = csv_of(&params, &format!("{kind}Key"));
    if !keys.is_empty() && listing.format == query::Format::Json {
        return match store::objects(&state.pool, request_library(), kind, &keys, true).await {
            Ok(value) => match current_headers(state).await {
                Ok(headers) => (headers, Json(value)).into_response(),
                Err(error) => server_error("read version", error),
            },
            Err(error) => server_error("read", error),
        };
    }
    let name_q = query_params
        .get("q")
        .map(str::trim)
        .filter(|q| !q.is_empty() && list_kind == query::ListKind::Collections);
    let page = store::query_named(&state.pool, request_library(), kind, &listing, name_q).await;
    listing_response(state, path, &query_params, &listing, list_kind, page).await
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

/// Answer a listing page in its format, always with `Total-Results` and, when
/// a page link applies, `Link` built against `path` (the public-URL endpoint).
/// versions is always 200 + map, never 304: the client's `getVersions` treats a
/// 304 as "no data" and restarts the sync forever.
async fn listing_response(
    state: &AppState,
    path: &str,
    params: &query::Params,
    listing: &query::Listing,
    kind: query::ListKind,
    page: sqlx::Result<(Vec<store::ListedObject>, i64)>,
) -> Response {
    let (objects, total) = match page {
        Ok(page) => page,
        Err(error) => return server_error("listing query", error),
    };
    let mut headers = match current_headers(state).await {
        Ok(headers) => headers,
        Err(error) => return server_error("listing version", error),
    };
    headers.insert("total-results", header_value(&total.to_string()));
    let base = format!("{}{}", state.config.public_url, path);
    let link_params = listing.link_params(params);
    if let Some(link) = link_header(&base, &link_params, listing.start, listing.limit, total) {
        headers.insert("link", header_value(&link));
    }
    match listing.format {
        query::Format::Json => match envelopes(state, kind, objects).await {
            Ok(values) => (headers, Json(values)).into_response(),
            Err(error) => server_error("listing envelopes", error),
        },
        // Zotero's `getKeys()` splits the body on '\n'; upstream ends it with one.
        query::Format::Keys => {
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/plain"),
            );
            let mut body: String = objects
                .iter()
                .map(|object| object.key.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            body.push('\n');
            (headers, body).into_response()
        }
        query::Format::Versions => {
            let map: serde_json::Map<String, Value> = objects
                .into_iter()
                .map(|object| (object.key, Value::from(object.version)))
                .collect();
            (headers, Json(Value::Object(map))).into_response()
        }
    }
}

/// Wrap a json page in the envelope for its kind, with one library lookup and
/// one count query per page.
async fn envelopes(
    state: &AppState,
    kind: query::ListKind,
    objects: Vec<store::ListedObject>,
) -> sqlx::Result<Vec<Value>> {
    let library = store::library_envelope(&state.pool, request_library()).await?;
    let base = &state.config.public_url;
    let keys: Vec<String> = objects.iter().map(|object| object.key.clone()).collect();
    Ok(match kind {
        query::ListKind::Items => {
            let children = store::child_counts(&state.pool, request_library(), &keys).await?;
            let notes = request_permissions().notes;
            objects
                .into_iter()
                .map(|item| {
                    let data = item.data.unwrap_or_default();
                    let primary = data
                        .get("itemType")
                        .and_then(Value::as_str)
                        .and_then(|t| SCHEMA.primary_creator_type(t));
                    envelope::item(
                        &library,
                        base,
                        item.version,
                        data,
                        children.get(&item.key).copied().unwrap_or_default(),
                        notes,
                        primary,
                    )
                })
                .collect()
        }
        query::ListKind::Collections => {
            let counts = store::collection_counts(&state.pool, request_library(), &keys).await?;
            objects
                .into_iter()
                .map(|object| {
                    let (collections, items) = counts.get(&object.key).copied().unwrap_or_default();
                    envelope::collection(
                        &library,
                        base,
                        object.version,
                        object.data.unwrap_or_default(),
                        collections,
                        items,
                    )
                })
                .collect()
        }
        query::ListKind::Searches => objects
            .into_iter()
            .map(|object| {
                envelope::search(
                    &library,
                    base,
                    object.version,
                    object.data.unwrap_or_default(),
                )
            })
            .collect(),
    })
}

/// Run an item listing and answer it.
async fn item_listing(
    state: &AppState,
    path: &str,
    params: &query::Params,
    q: &query::ItemQuery,
) -> Response {
    let page = store::query_items(
        &state.pool,
        request_library(),
        q,
        request_permissions().notes,
    )
    .await;
    listing_response(
        state,
        path,
        params,
        &q.listing,
        query::ListKind::Items,
        page,
    )
    .await
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
