use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::s3;

pub(crate) fn server_error(context: &str, error: sqlx::Error) -> Response {
    tracing::error!(%error, context, "database error");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// A listing request with a format, sort, direction or `since` xotero does not
/// serve. `headers` carries the library's `Last-Modified-Version`.
pub(crate) fn unsupported(mut headers: HeaderMap) -> Response {
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    (
        StatusCode::BAD_REQUEST,
        headers,
        r#"{"error":"Unsupported API combination"}"#,
    )
        .into_response()
}

pub(crate) fn s3_error(context: &str, error: s3::S3Error) -> Response {
    tracing::error!(%error, context, "object storage error");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
