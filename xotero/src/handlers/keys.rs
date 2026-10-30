use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Map, Value};

use super::web_session::{digest, session_proof, singleton};
use crate::domain::{
    AdminAudit, ApiKeyId, CreateKey, KeyAction, KeyProof, Permissions, RequestContext, UserId,
};
use crate::error::server_error;
use crate::{store, AppState};

/// Zotero omits false permission fields and empty access families.
fn access_payload(permissions: Permissions, group_grants: &[store::GroupGrant]) -> Value {
    let mut user = Map::new();
    for (name, allowed) in [
        ("library", permissions.library),
        ("files", permissions.files),
        ("notes", permissions.notes),
        ("write", permissions.write),
    ] {
        if allowed {
            user.insert(name.into(), Value::Bool(true));
        }
    }
    let mut access = Map::new();
    if !user.is_empty() {
        access.insert("user".into(), Value::Object(user));
    }
    let mut groups = Map::new();
    for grant in group_grants.iter().filter(|grant| grant.library) {
        groups.insert(
            grant
                .group_id
                .map_or_else(|| "all".to_string(), |id| id.get().to_string()),
            json!({ "library": true, "write": grant.write }),
        );
    }
    if !groups.is_empty() {
        access.insert("groups".into(), Value::Object(groups));
    }
    Value::Object(access)
}

pub(crate) async fn key_current(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
) -> Response {
    let group_grants = match context.api_key_id {
        Some(api_key_id) => match store::api_key_group_grants(&state.pool, api_key_id).await {
            Ok(grants) => grants,
            Err(error) => return server_error("read API key group grants", error),
        },
        None if context.permissions.library => vec![store::GroupGrant {
            group_id: None,
            library: true,
            write: context.permissions.write,
        }],
        None => Vec::new(),
    };
    Json(json!({
        "key": context.presented_key,
        "userID": context.principal.user_id.get(),
        "username": context.principal.username,
        "displayName": context.principal.display_name,
        "access": access_payload(context.permissions, &group_grants),
    }))
    .into_response()
}

fn failure() -> Response {
    tracing::error!("key management operation failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn denied(
    state: &AppState,
    audit: &AdminAudit,
    action: KeyAction,
    target: store::ApiKeyTarget,
    status: StatusCode,
) -> Response {
    let target = match target {
        store::ApiKeyTarget::Named(key) => Some(key),
        store::ApiKeyTarget::None | store::ApiKeyTarget::Current => None,
    };
    match store::deny_key(&state.pool, audit, action, target).await {
        Ok(()) => status.into_response(),
        Err(_) => failure(),
    }
}

fn denial_status(denial: store::AdminDenial) -> StatusCode {
    match denial {
        store::AdminDenial::Unauthenticated => StatusCode::UNAUTHORIZED,
        store::AdminDenial::Unauthorized => StatusCode::FORBIDDEN,
    }
}

pub(crate) async fn manage(State(state): State<AppState>, request: Request) -> Response {
    let mut response = handle(&state, request).await;
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

async fn handle(state: &AppState, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let path: Vec<_> = parts.uri.path().split('/').collect();
    let (action, admin, raw_user, raw_key, current) = match (parts.method.clone(), path.as_slice())
    {
        (Method::GET, ["", "xotero", "me", "keys"]) => (KeyAction::List, false, None, None, false),
        (Method::POST, ["", "xotero", "me", "keys"]) => {
            (KeyAction::Create, false, None, None, false)
        }
        (Method::DELETE, ["", "xotero", "me", "keys", key]) => {
            (KeyAction::Revoke, false, None, Some(*key), false)
        }
        (Method::GET, ["", "xotero", "admin", "users", user, "keys"]) => {
            (KeyAction::List, true, Some(*user), None, false)
        }
        (Method::DELETE, ["", "xotero", "admin", "users", user, "keys", key]) => {
            (KeyAction::Revoke, true, Some(*user), Some(*key), false)
        }
        (Method::DELETE, ["", "keys", "current"]) => (KeyAction::Revoke, false, None, None, true),
        _ => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    let mut audit = match store::admin_audit(&state.pool).await {
        Ok(audit) => audit,
        Err(_) => return failure(),
    };
    let mut target = if current {
        store::ApiKeyTarget::Current
    } else {
        store::ApiKeyTarget::None
    };
    if let Some(raw) = raw_key {
        target = match raw.parse().ok().and_then(ApiKeyId::new) {
            Some(key) => store::ApiKeyTarget::Named(key),
            None => return denied(state, &audit, action, target, StatusCode::BAD_REQUEST).await,
        };
    }
    if let Some(raw) = raw_user {
        audit.subject = match raw.parse().ok().and_then(UserId::new) {
            Some(user) => Some(user),
            None => return denied(state, &audit, action, target, StatusCode::BAD_REQUEST).await,
        };
    }
    let proof = if admin {
        session_proof(
            &parts.headers,
            &state.config.web_origin,
            parts.method != Method::GET,
        )
        .map(KeyProof::Session)
    } else if parts.headers.contains_key("zotero-api-key") {
        match singleton(&parts.headers, "zotero-api-key") {
            Some(token) => {
                let hash = digest(token);
                if state.config.recovery_permissions(&hash).is_some() {
                    Err(StatusCode::FORBIDDEN)
                } else {
                    Ok(KeyProof::Database(hash))
                }
            }
            None => Err(StatusCode::UNAUTHORIZED),
        }
    } else if current {
        Err(StatusCode::UNAUTHORIZED)
    } else {
        session_proof(
            &parts.headers,
            &state.config.web_origin,
            parts.method != Method::GET,
        )
        .map(KeyProof::Session)
    };
    let proof = match proof {
        Ok(proof) => proof,
        Err(status) => return denied(state, &audit, action, target, status).await,
    };
    let guard = if admin {
        let KeyProof::Session(proof) = &proof else {
            return failure();
        };
        store::admin_key_guard(&state.pool, proof, &mut audit, target).await
    } else {
        store::key_guard(&state.pool, &proof, &mut audit, target, None).await
    };
    let guard = match guard {
        Ok(Ok(guard)) => guard,
        Ok(Err(reason)) => {
            return denied(state, &audit, action, target, denial_status(reason)).await
        }
        Err(_) => return failure(),
    };
    match action {
        KeyAction::List => match guard.list().await {
            Ok(Some(keys)) => Json(keys).into_response(),
            Ok(None) => StatusCode::NOT_FOUND.into_response(),
            Err(_) => failure(),
        },
        KeyAction::Revoke => match guard.revoke().await {
            Ok(true) => StatusCode::NO_CONTENT.into_response(),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(_) => failure(),
        },
        KeyAction::Create => {
            if guard.admit().await.is_err() {
                return failure();
            }
            let bytes =
                match crate::http::middleware::buffered_body(body, &parts.headers, 1024 * 1024)
                    .await
                {
                    Ok(bytes) => bytes,
                    Err(status) => return denied(state, &audit, action, target, status).await,
                };
            let input: CreateKey = match serde_json::from_slice::<CreateKey>(&bytes) {
                Ok(input) if input.valid() => input,
                _ => return denied(state, &audit, action, target, StatusCode::BAD_REQUEST).await,
            };
            let guard = match store::key_guard(&state.pool, &proof, &mut audit, target, Some(input))
                .await
            {
                Ok(Ok(guard)) => guard,
                Ok(Err(reason)) => {
                    return denied(state, &audit, action, target, denial_status(reason)).await
                }
                Err(_) => return failure(),
            };
            use tokio::io::AsyncReadExt;
            let mut random = [0u8; 32];
            let Ok(mut rng) = tokio::fs::File::open("/dev/urandom").await else {
                return failure();
            };
            if rng.read_exact(&mut random).await.is_err() {
                return failure();
            }
            let token: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            match guard.issue(&digest(&token)).await {
                Ok(mut metadata) => {
                    metadata["token"] = Value::String(token);
                    (StatusCode::CREATED, Json(metadata)).into_response()
                }
                Err(_) => failure(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_requires_explicit_scope_without_duplicates_or_defaults() {
        let user = r#""user":{"library":true,"notes":false,"write":false,"files":false}"#;
        let groups = r#""groups":{"all":{"library":false,"write":false},"individual":[]}"#;
        let valid = format!(r#"{{"name":"Named","access":{{{user},{groups}}}}}"#);
        let parsed: CreateKey = serde_json::from_str(&valid).unwrap();
        assert!(parsed.valid());
        for body in [
            r#"{"name":"Missing"}"#.to_owned(),
            format!(r#"{{"name":"Missing","access":{{{user}}}}}"#),
            valid.replace(r#""notes":false,"#, ""),
            valid.replace(r#""write":false"#, r#""write":false,"write":true"#),
            valid.replace(r#""library":true"#, r#""library":null"#),
            valid.replace(r#""name":"Named""#, r#""name":"Named","userID":1"#),
        ] {
            assert!(serde_json::from_str::<CreateKey>(&body).is_err());
        }
    }
}
