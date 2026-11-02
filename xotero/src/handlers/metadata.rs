use std::collections::HashMap;

use axum::{
    extract::Query,
    http::{header, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;

use crate::metadata::{creator_fields, Invalid, SCHEMA, SCHEMA_JSON};

type Params = Query<HashMap<String, String>>;

fn schema_version() -> [(HeaderName, HeaderValue); 1] {
    [(
        HeaderName::from_static("zotero-schema-version"),
        HeaderValue::from(SCHEMA.version),
    )]
}

fn reply(result: Result<Value, Invalid>) -> Response {
    match result {
        Ok(value) => (schema_version(), Json(value)).into_response(),
        Err(Invalid(message)) => (StatusCode::BAD_REQUEST, message).into_response(),
    }
}

fn param<'a>(params: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    params.get(name).map(String::as_str)
}

/// `GET /schema`: the pinned schema file, byte for byte.
pub(crate) async fn schema() -> Response {
    (
        schema_version(),
        [(header::CONTENT_TYPE, "application/json")],
        SCHEMA_JSON,
    )
        .into_response()
}

/// `GET /itemTypes`
pub(crate) async fn item_types(Query(params): Params) -> Response {
    reply(Ok(SCHEMA.item_types_list(param(&params, "locale"))))
}

/// `GET /itemFields`
pub(crate) async fn item_fields(Query(params): Params) -> Response {
    reply(Ok(SCHEMA.item_fields(param(&params, "locale"))))
}

/// `GET /creatorFields`
pub(crate) async fn creator_field_names() -> Response {
    reply(Ok(creator_fields()))
}

/// `GET /itemTypeFields?itemType=`
pub(crate) async fn item_type_fields(Query(params): Params) -> Response {
    reply(SCHEMA.item_type_fields(param(&params, "itemType"), param(&params, "locale")))
}

/// `GET /itemTypeCreatorTypes?itemType=`
pub(crate) async fn item_type_creator_types(Query(params): Params) -> Response {
    reply(SCHEMA.item_type_creator_types(param(&params, "itemType"), param(&params, "locale")))
}

/// `GET /items/new?itemType=` with `linkMode` or `annotationType` where required.
pub(crate) async fn new_item(Query(params): Params) -> Response {
    reply(SCHEMA.template(
        param(&params, "itemType"),
        param(&params, "linkMode"),
        param(&params, "annotationType"),
    ))
}
