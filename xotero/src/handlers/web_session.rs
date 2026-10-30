use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use sha2::{Digest, Sha256};

use crate::{store, AppState};

const BROWSER: &str = "__Host-xotero-browser";
const SESSION: &str = "__Host-xotero-session";

fn singleton<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok().filter(|v| !v.is_empty())?;
    values.next().is_none().then_some(value)
}

fn cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>, ()> {
    let mut found = None;
    for value in headers.get_all("cookie") {
        for entry in value.to_str().map_err(|_| ())?.split(';') {
            if let Some((key, value)) = entry.trim().split_once('=') {
                if key == name {
                    if found.is_some() || !valid_token(value) {
                        return Err(());
                    }
                    found = Some(value.to_owned());
                }
            }
        }
    }
    Ok(found)
}

fn valid_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

async fn random_token() -> std::io::Result<String> {
    use tokio::io::AsyncReadExt;
    let mut bytes = [0u8; 32];
    tokio::fs::File::open("/dev/urandom")
        .await?
        .read_exact(&mut bytes)
        .await?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn set_cookie(response: &mut Response, name: &str, token: &str, lifetime: u32) {
    let value =
        format!("{name}={token}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={lifetime}");
    // Names and attributes are constants; tokens are locally generated hex.
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().append(SET_COOKIE, value);
    }
}

fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

fn failure() -> Response {
    // SQLx errors may contain failing rows or identity claims. Never log them.
    tracing::error!("Web session operation failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn same_origin(state: &AppState, headers: &HeaderMap) -> bool {
    singleton(headers, "origin") == Some(state.config.web_origin.as_str())
}

async fn forbidden(state: &AppState, action: store::WebSessionAction) -> Response {
    match store::deny_web_session(&state.pool, action).await {
        Ok(()) => StatusCode::FORBIDDEN.into_response(),
        Err(_) => failure(),
    }
}

pub(crate) async fn challenge(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let browser = match cookie(&headers, BROWSER) {
        Ok(Some(browser)) => browser,
        Ok(None) => match random_token().await {
            Ok(token) => token,
            Err(_) => return failure(),
        },
        Err(()) => return forbidden(&state, store::WebSessionAction::Login).await,
    };
    let csrf = match random_token().await {
        Ok(token) => token,
        Err(_) => return failure(),
    };
    if store::create_web_challenge(
        &state.pool,
        &digest(&browser),
        &digest(&csrf),
        &state.config.web_origin,
    )
    .await
    .is_err()
    {
        return failure();
    }
    let mut response = Json(serde_json::json!({"csrfToken":csrf})).into_response();
    set_cookie(&mut response, BROWSER, &browser, 28800);
    private(response)
}

pub(crate) async fn login(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !same_origin(&state, &headers) {
        return forbidden(&state, store::WebSessionAction::Login).await;
    }
    let claims = singleton(&headers, "x-xotero-oidc-issuer")
        .zip(singleton(&headers, "x-xotero-oidc-subject"));
    let (Some((issuer, subject)), Some(challenge), Ok(Some(browser)), Ok(previous)) = (
        claims,
        singleton(&headers, "x-xotero-csrf").filter(|v| valid_token(v)),
        cookie(&headers, BROWSER),
        cookie(&headers, SESSION),
    ) else {
        return forbidden(&state, store::WebSessionAction::Login).await;
    };
    let (Ok(token), Ok(csrf), Ok(credential)) = (
        random_token().await,
        random_token().await,
        random_token().await,
    ) else {
        return failure();
    };
    let previous = previous.as_deref().map(digest);
    let result = store::complete_web_login(
        &state.pool,
        store::WebLogin {
            browser: &digest(&browser),
            challenge: &digest(challenge),
            previous: previous.as_ref(),
            issuer,
            subject,
            origin: &state.config.web_origin,
            token: &digest(&token),
            csrf: &digest(&csrf),
            credential: &digest(&credential),
        },
    )
    .await;
    match result {
        Ok(Some(user)) => {
            let mut response =
                Json(serde_json::json!({"csrfToken":csrf,"userID":user})).into_response();
            set_cookie(&mut response, SESSION, &token, 28800);
            set_cookie(&mut response, BROWSER, &browser, 28800);
            private(response)
        }
        Ok(None) => StatusCode::FORBIDDEN.into_response(),
        Err(_) => failure(),
    }
}

pub(crate) async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !same_origin(&state, &headers) {
        return forbidden(&state, store::WebSessionAction::Logout).await;
    }
    let (Ok(Some(browser)), Ok(Some(token)), Some(csrf)) = (
        cookie(&headers, BROWSER),
        cookie(&headers, SESSION),
        singleton(&headers, "x-xotero-csrf").filter(|v| valid_token(v)),
    ) else {
        return forbidden(&state, store::WebSessionAction::Logout).await;
    };
    match store::logout_web_session(
        &state.pool,
        &digest(&browser),
        &digest(&token),
        &digest(csrf),
        &state.config.web_origin,
    )
    .await
    {
        Ok(true) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            set_cookie(&mut response, SESSION, "", 0);
            private(response)
        }
        Ok(false) => StatusCode::FORBIDDEN.into_response(),
        Err(_) => failure(),
    }
}
