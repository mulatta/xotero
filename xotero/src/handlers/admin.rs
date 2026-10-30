use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use super::web_session::session_proof;
use crate::domain::{
    AdminAction, AdminAudit, CreateUser, ExternalIdentity, SetInstanceAdmin, UpdateUser, UserId,
};
use crate::http::middleware::buffered_body;
use crate::{store, AppState};

fn failure() -> Response {
    // Database errors may contain identity claims or failing request values.
    tracing::error!("admin operation failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn deny(state: &AppState, event: (AdminAction, &AdminAudit), status: StatusCode) -> Response {
    match store::deny_admin(&state.pool, event.0, event.1).await {
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

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, StatusCode> {
    serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)
}

fn parse(action: AdminAction, body: &[u8]) -> Result<store::AdminMutation, StatusCode> {
    match action {
        AdminAction::Create => decode::<CreateUser>(body).map(store::AdminMutation::Create),
        AdminAction::Update => {
            let input: UpdateUser = decode(body)?;
            if input.display_name.is_none() && input.disabled.is_none() {
                return Err(StatusCode::BAD_REQUEST);
            }
            Ok(store::AdminMutation::Update(input))
        }
        AdminAction::Role => decode::<SetInstanceAdmin>(body).map(store::AdminMutation::Role),
        AdminAction::Link => decode::<ExternalIdentity>(body).map(store::AdminMutation::Link),
        AdminAction::Unlink => decode::<ExternalIdentity>(body).map(store::AdminMutation::Unlink),
        AdminAction::List => Err(StatusCode::BAD_REQUEST),
    }
}

pub(crate) async fn users(State(state): State<AppState>, request: Request) -> Response {
    let mut response = handle(&state, request).await;
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

async fn handle(state: &AppState, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let path: Vec<_> = parts.uri.path().split('/').collect();
    let (action, raw_target) = match (parts.method.clone(), path.as_slice()) {
        (Method::GET, ["", "xotero", "admin", "users"]) => (AdminAction::List, None),
        (Method::POST, ["", "xotero", "admin", "users"]) => (AdminAction::Create, None),
        (Method::PATCH, ["", "xotero", "admin", "users", id]) => (AdminAction::Update, Some(*id)),
        (Method::PUT, ["", "xotero", "admin", "users", id, "instance-admin"]) => {
            (AdminAction::Role, Some(*id))
        }
        (Method::POST, ["", "xotero", "admin", "users", id, "identities"]) => {
            (AdminAction::Link, Some(*id))
        }
        (Method::DELETE, ["", "xotero", "admin", "users", id, "identities"]) => {
            (AdminAction::Unlink, Some(*id))
        }
        _ => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    let mut audit = match store::admin_audit(&state.pool).await {
        Ok(audit) => audit,
        Err(_) => return failure(),
    };
    audit.subject = match raw_target {
        Some(id) => match id.parse::<i64>().ok().and_then(UserId::new) {
            Some(id) => Some(id),
            None => return deny(state, (action, &audit), StatusCode::BAD_REQUEST).await,
        },
        None => None,
    };
    let proof = match session_proof(
        &parts.headers,
        &state.config.web_origin,
        parts.method != Method::GET,
    ) {
        Ok(proof) => proof,
        Err(status) => return deny(state, (action, &audit), status).await,
    };
    let guard = match store::admin_guard(&state.pool, &proof, &mut audit).await {
        Ok(Ok(guard)) => guard,
        Ok(Err(denial)) => return deny(state, (action, &audit), denial_status(denial)).await,
        Err(_) => return failure(),
    };
    if matches!(action, AdminAction::List) {
        return match guard.list().await {
            Ok(users) => Json(users).into_response(),
            Err(_) => failure(),
        };
    }
    if guard.admit().await.is_err() {
        return failure();
    }
    // Admission precedes even the first body poll, but is not authorization for
    // a later mutation. No locks or database transaction span body collection.
    let bytes = match buffered_body(body, &parts.headers, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(status) => return deny(state, (action, &audit), status).await,
    };
    let mutation = match parse(action, &bytes) {
        Ok(mutation) => mutation,
        Err(status) => return deny(state, (action, &audit), status).await,
    };
    let guard = match store::admin_guard(&state.pool, &proof, &mut audit).await {
        Ok(Ok(guard)) => guard,
        Ok(Err(denial)) => return deny(state, (action, &audit), denial_status(denial)).await,
        Err(_) => return failure(),
    };
    match guard.mutate(audit.subject, mutation).await {
        Ok(store::AdminResult::Created { user, library }) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"userID":user,"libraryID":library})),
        )
            .into_response(),
        Ok(store::AdminResult::Changed) => StatusCode::NO_CONTENT.into_response(),
        Ok(store::AdminResult::Missing) => StatusCode::NOT_FOUND.into_response(),
        Ok(store::AdminResult::Conflict) => StatusCode::CONFLICT.into_response(),
        Err(_) => failure(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_rejects_unknown_duplicate_null_and_wrong_types() {
        // Given malformed changes, parsing must not silently drop fields.
        for body in [
            r#"{}"#,
            r#"{"unknown":true}"#,
            r#"{"disabled":null}"#,
            r#"{"displayName":null}"#,
            r#"{"disabled":"true"}"#,
            r#"{"disabled":true,"disabled":false}"#,
            r#"{"displayName":" "}"#,
        ] {
            // When the boundary parses the change, then it rejects it.
            assert!(matches!(
                parse(AdminAction::Update, body.as_bytes()),
                Err(StatusCode::BAD_REQUEST)
            ));
        }
    }

    #[test]
    fn create_preserves_exact_identity_and_requires_mapping() {
        // Given an explicitly provisioned identity with meaningful whitespace.
        let body =
            br#"{"username":"new","displayName":"New","issuer":" issuer ","subject":"Subject"}"#;
        // When parsed, then exact claims survive without normalization.
        let store::AdminMutation::Create(input) = parse(AdminAction::Create, body).unwrap() else {
            panic!("wrong mutation");
        };
        assert_eq!(input.issuer, " issuer ");
        assert_eq!(input.subject, "Subject");
        assert!(parse(
            AdminAction::Create,
            br#"{"username":"new","displayName":"New"}"#
        )
        .is_err());
    }
}
