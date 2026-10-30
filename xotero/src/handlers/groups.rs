use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Map, Value};

use crate::domain::{GroupId, RequestContext, UserId};
use crate::error::server_error;
use crate::http::headers::{header_value, version_headers};
use crate::{store, AppState};

use crate::domain::{GroupAction, GroupChanges, GroupTarget};

fn management_failure() -> Response {
    // SQL errors may contain request values or failed rows.
    tracing::error!("group management failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn group_denial(denial: store::GroupDenial) -> StatusCode {
    match denial {
        store::GroupDenial::Unauthenticated => StatusCode::UNAUTHORIZED,
        store::GroupDenial::Unauthorized => StatusCode::FORBIDDEN,
        store::GroupDenial::Missing => StatusCode::NOT_FOUND,
        store::GroupDenial::Conflict => StatusCode::CONFLICT,
        store::GroupDenial::Stale => StatusCode::PRECONDITION_FAILED,
    }
}

async fn deny_management(
    state: &AppState,
    audit: &crate::domain::AdminAudit,
    target: GroupTarget,
    status: StatusCode,
) -> Response {
    match store::deny_group(&state.pool, audit, target).await {
        Ok(()) => status.into_response(),
        Err(_) => management_failure(),
    }
}

fn metadata_version(headers: &HeaderMap) -> Result<i64, StatusCode> {
    if !headers.contains_key("if-match") {
        return Err(StatusCode::PRECONDITION_REQUIRED);
    }
    let value = super::web_session::singleton(headers, "if-match")
        .and_then(|value| value.strip_prefix('"'))
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0);
    value.ok_or(StatusCode::BAD_REQUEST)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupCreation {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    url: String,
    #[serde(default, rename = "libraryEditing")]
    library_editing: Option<String>,
    #[serde(default, rename = "fileEditing")]
    file_editing: Option<String>,
    #[serde(default, rename = "ownerUserID")]
    owner: Option<i64>,
}

fn group_input(
    action: GroupAction,
    admin: bool,
    bytes: &[u8],
) -> Result<(GroupChanges, Option<UserId>), StatusCode> {
    let invalid = || StatusCode::BAD_REQUEST;
    let (changes, owner) = match action {
        GroupAction::Create => {
            let input: GroupCreation = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            // Option alone accepts explicit null. Create has optional defaults,
            // but null and ownerUserID on the ordinary route are never defaults.
            let raw: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            if raw
                .as_object()
                .is_none_or(|object| object.values().any(Value::is_null))
                || (!admin && raw.get("ownerUserID").is_some())
                || input.name.trim().is_empty()
                || input.name.contains('\0')
                || input.description.contains('\0')
                || input.url.contains('\0')
            {
                return Err(invalid());
            }
            let owner = match (admin, input.owner) {
                (true, Some(owner)) => Some(UserId::new(owner).ok_or_else(invalid)?),
                (true, None) => return Err(invalid()),
                (false, _) => None,
            };
            (
                GroupChanges {
                    name: Some(input.name),
                    description: Some(input.description),
                    url: Some(input.url),
                    library_editing: input.library_editing,
                    file_editing: input.file_editing,
                },
                owner,
            )
        }
        GroupAction::Update => (
            serde_json::from_slice::<GroupChanges>(bytes).map_err(|_| invalid())?,
            None,
        ),
        GroupAction::Delete => {
            if !bytes.is_empty() {
                return Err(invalid());
            }
            return Ok((GroupChanges::default(), None));
        }
        GroupAction::List | GroupAction::Read => return Err(invalid()),
    };
    if !changes.valid() {
        return Err(invalid());
    }
    Ok((changes, owner))
}

pub(crate) async fn manage(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response {
    let mut response = manage_request(&state, request).await;
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn manage_request(state: &AppState, request: axum::extract::Request) -> Response {
    use axum::http::Method;
    let (parts, body) = request.into_parts();
    let segments: Vec<_> = parts.uri.path().split('/').collect();
    let (admin, raw_id) = match segments.as_slice() {
        ["", "xotero", "groups"] => (false, None),
        ["", "xotero", "groups", id] => (false, Some(*id)),
        ["", "xotero", "admin", "groups"] => (true, None),
        ["", "xotero", "admin", "groups", id] => (true, Some(*id)),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let action = match (&parts.method, raw_id) {
        (&Method::GET, None) => GroupAction::List,
        (&Method::GET, Some(_)) => GroupAction::Read,
        (&Method::POST, None) => GroupAction::Create,
        (&Method::PATCH, Some(_)) => GroupAction::Update,
        (&Method::DELETE, Some(_)) => GroupAction::Delete,
        _ => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    let mut audit = match store::admin_audit(&state.pool).await {
        Ok(audit) => audit,
        Err(_) => return management_failure(),
    };
    let mut target = GroupTarget {
        admin,
        action,
        id: None,
        owner: None,
        expected: None,
    };
    if let Some(raw_id) = raw_id {
        target.id = raw_id.parse().ok().and_then(GroupId::new);
        if target.id.is_none() {
            return deny_management(state, &audit, target, StatusCode::BAD_REQUEST).await;
        }
    }
    let proof = match super::web_session::session_proof(
        &parts.headers,
        &state.config.web_origin,
        action.mutation(),
    ) {
        Ok(proof) => proof,
        Err(status) => return deny_management(state, &audit, target, status).await,
    };
    if matches!(action, GroupAction::Update | GroupAction::Delete) {
        target.expected = match metadata_version(&parts.headers) {
            Ok(version) => Some(version),
            Err(status) => return deny_management(state, &audit, target, status).await,
        };
    }
    let guard = match store::group_guard(&state.pool, &proof, &mut audit, target).await {
        Ok(Ok(guard)) => guard,
        Ok(Err(denial)) => return group_denial(denial).into_response(),
        Err(_) => return management_failure(),
    };
    if !action.mutation() {
        return match guard.read().await {
            Ok(mut groups) => match action {
                GroupAction::Read => match groups.pop() {
                    Some(group) => {
                        let mut headers = HeaderMap::new();
                        headers.insert("etag", header_value(&format!("\"{}\"", group["version"])));
                        (headers, Json(group)).into_response()
                    }
                    None => StatusCode::NOT_FOUND.into_response(),
                },
                GroupAction::List => {
                    let mut headers = HeaderMap::new();
                    headers.insert("total-results", header_value(&groups.len().to_string()));
                    (headers, Json(groups)).into_response()
                }
                GroupAction::Create | GroupAction::Update | GroupAction::Delete => {
                    management_failure()
                }
            },
            Err(_) => management_failure(),
        };
    }
    if guard.admit().await.is_err() {
        return management_failure();
    }
    let bytes =
        match crate::http::middleware::buffered_body(body, &parts.headers, 1024 * 1024).await {
            Ok(bytes) => bytes,
            Err(status) => return deny_management(state, &audit, target, status).await,
        };
    let (changes, owner) = match group_input(action, admin, &bytes) {
        Ok(input) => input,
        Err(status) => return deny_management(state, &audit, target, status).await,
    };
    target.owner = owner;
    let guard = match store::group_guard(&state.pool, &proof, &mut audit, target).await {
        Ok(Ok(guard)) => guard,
        Ok(Err(denial)) => return group_denial(denial).into_response(),
        Err(_) => return management_failure(),
    };
    match guard.mutate(&proof, changes).await {
        Ok(Ok(Some(created))) => (StatusCode::CREATED, Json(created)).into_response(),
        Ok(Ok(None)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(denial)) => group_denial(denial).into_response(),
        Err(_) => management_failure(),
    }
}

fn group_json(group: store::GroupMetadata, public_url: &str) -> Value {
    let mut data = Map::new();
    data.insert("id".into(), Value::from(group.id.get()));
    data.insert("version".into(), Value::from(group.version));
    data.insert("name".into(), Value::from(group.name));
    data.insert("owner".into(), Value::from(group.owner));
    data.insert("type".into(), Value::from(group.group_type));
    data.insert("description".into(), Value::from(group.description));
    data.insert("url".into(), Value::from(group.url));
    data.insert("libraryEditing".into(), Value::from(group.library_editing));
    data.insert("libraryReading".into(), Value::from(group.library_reading));
    data.insert("fileEditing".into(), Value::from(group.file_editing));
    if !group.admins.is_empty() {
        data.insert("admins".into(), json!(group.admins));
    }
    if !group.members.is_empty() {
        data.insert("members".into(), json!(group.members));
    }
    json!({
        "id": group.id.get(),
        "version": group.version,
        "links": {
            "self": {
                "href": format!("{public_url}/groups/{}", group.id.get()),
                "type": "application/json"
            },
            "alternate": {
                "href": format!("https://www.zotero.org/groups/{}", group.id.get()),
                "type": "text/html"
            }
        },
        "meta": {
            "created": group.created,
            "lastModified": group.last_modified,
            "numItems": group.num_items,
            "isAdmin": matches!(group.role.as_str(), "owner" | "admin")
        },
        "data": Value::Object(data),
    })
}

pub(crate) async fn groups(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path(target_user_id): Path<i64>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(target_user_id) = UserId::new(target_user_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match store::active_user_exists(&state.pool, target_user_id).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return server_error("read group-list user", error),
    }
    let groups = match store::groups_for_user(
        &state.pool,
        target_user_id,
        context.principal.user_id,
        context.api_key_id,
        context.api_key_id.is_none() && context.permissions.library,
    )
    .await
    {
        Ok(groups) => groups,
        Err(error) => return server_error("list groups", error),
    };
    let mut headers = HeaderMap::new();
    headers.insert("total-results", header_value(&groups.len().to_string()));
    headers.insert(
        "link",
        header_value(&format!(
            "<{}/users/{}/groups>; rel=\"alternate\"",
            state.config.public_url,
            target_user_id.get()
        )),
    );
    if params
        .get("format")
        .is_some_and(|format| format == "versions")
    {
        let versions = groups
            .into_iter()
            .map(|group| (group.id.get().to_string(), Value::from(group.version)))
            .collect();
        (headers, Json(Value::Object(versions))).into_response()
    } else {
        let values: Vec<_> = groups
            .into_iter()
            .map(|group| group_json(group, &state.config.public_url))
            .collect();
        (headers, Json(values)).into_response()
    }
}

pub(crate) async fn group_get(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path(group_id): Path<i64>,
) -> Response {
    let Some(group_id) = GroupId::new(group_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match store::group_for_user(
        &state.pool,
        group_id,
        context.principal.user_id,
        context.api_key_id,
        context.api_key_id.is_none() && context.permissions.library,
    )
    .await
    {
        Ok(Some(group)) => (
            version_headers(group.version),
            Json(group_json(group, &state.config.public_url)),
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => server_error("read group", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_precondition_rejects_weak_multiple_and_nonpositive_versions() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            metadata_version(&headers),
            Err(StatusCode::PRECONDITION_REQUIRED)
        );
        for value in [
            "1",
            "*",
            "W/\"1\"",
            "\"0\"",
            "\"-1\"",
            "\"1\", \"2\"",
            "\"+1\"",
        ] {
            headers.insert("if-match", value.parse().unwrap());
            assert_eq!(metadata_version(&headers), Err(StatusCode::BAD_REQUEST));
        }
        headers.insert("if-match", "\"7\"".parse().unwrap());
        assert_eq!(metadata_version(&headers), Ok(7));
        headers.append("if-match", "\"7\"".parse().unwrap());
        assert_eq!(metadata_version(&headers), Err(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn metadata_input_rejects_owner_mutation_duplicate_and_null_fields() {
        for bytes in [
            r#"{}"#,
            r#"{"name":null}"#,
            r#"{"description":null}"#,
            r#"{"name":"a","name":"b"}"#,
            r#"{"ownerUserID":1}"#,
            r#"{"libraryReading":"all"}"#,
            r#"{"libraryEditing":"none"}"#,
            r#"{"fileEditing":"all"}"#,
            r#"{"fileEditing":null}"#,
        ] {
            assert!(group_input(GroupAction::Update, false, bytes.as_bytes()).is_err());
        }
        assert!(group_input(GroupAction::Update, false, br#"{"description":""}"#).is_ok());
    }

    #[test]
    fn creation_requires_owner_only_on_explicit_admin_route() {
        let owner = br#"{"name":"Private","ownerUserID":101}"#;
        assert!(group_input(GroupAction::Create, true, owner).is_ok());
        assert!(group_input(GroupAction::Create, false, owner).is_err());
        assert!(group_input(GroupAction::Create, true, br#"{"name":"Private"}"#).is_err());
        for bytes in [
            r#"{"name":" "}"#,
            r#"{"name":"Private","fileEditing":null}"#,
            r#"{"name":"Private","ownerUserID":null}"#,
            r#"{"name":"Private","name":"Duplicate"}"#,
        ] {
            assert!(group_input(GroupAction::Create, false, bytes.as_bytes()).is_err());
        }
        assert!(group_input(GroupAction::Create, false, br#"{"name":"Private"}"#).is_ok());
    }
}
