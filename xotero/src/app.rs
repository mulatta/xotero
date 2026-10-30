use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::HeaderMap,
    middleware,
    routing::{delete as route_delete, get, patch, post, put},
    Extension, Router,
};
use sqlx::PgPool;

use crate::config::Config;
use crate::handlers::files::{file_get, file_post, upload_put};
use crate::handlers::fulltext::{fulltext_item, fulltext_versions, fulltext_write};
use crate::handlers::groups::{group_get, groups};
use crate::handlers::keys::{key_current, manage};
use crate::handlers::login::{
    cancel_session, check_session, create_session, login_authorize, login_page,
};
use crate::handlers::objects::{
    collection_items, collection_items_top, delete, items_get, items_top, items_trash, read, write,
};
use crate::handlers::settings::{deleted, settings_delete, settings_read, settings_write};
use crate::handlers::tags::{tags_delete, tags_get};
use crate::http::middleware::{log_and_auth, MAX_BODY};
use crate::s3;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) pool: PgPool,
    pub(crate) storage: Arc<s3::Storage>,
    pub(crate) uploads: Arc<tokio::sync::Semaphore>,
}

/// An unguessable upload token (128 bits of OS randomness, hex-encoded). `None`
/// if the OS RNG can't be read, so the caller can fail the request rather than
/// panic.
pub(crate) fn router(state: AppState) -> Router {
    // Each object kind shares the read/write/delete logic; the closures bind the
    // kind so the handlers stay generic.
    let objects = |kind: &'static str| {
        get(
            move |State(state): State<AppState>,
                  Query(p): Query<HashMap<String, String>>| async move {
                read(&state, kind, p).await
            },
        )
        .post(
            move |State(state): State<AppState>, Extension(context): Extension<crate::domain::RequestContext>, headers: HeaderMap, body: Bytes| async move {
                write(&state, &context, kind, headers, body).await
            },
        )
        .patch(
            move |State(state): State<AppState>, Extension(context): Extension<crate::domain::RequestContext>, headers: HeaderMap, body: Bytes| async move {
                write(&state, &context, kind, headers, body).await
            },
        )
            .delete(
                move |State(state): State<AppState>,
                      Extension(context): Extension<crate::domain::RequestContext>,
                      headers: HeaderMap,
                      Query(p): Query<HashMap<String, String>>| async move {
                    delete(&state, &context, kind, headers, p).await
                },
            )
    };
    Router::new()
        .route(
            "/xotero/groups",
            get(crate::handlers::groups::manage).post(crate::handlers::groups::manage),
        )
        .route(
            "/xotero/groups/{id}",
            get(crate::handlers::groups::manage)
                .patch(crate::handlers::groups::manage)
                .delete(crate::handlers::groups::manage),
        )
        .route(
            "/xotero/admin/groups",
            get(crate::handlers::groups::manage).post(crate::handlers::groups::manage),
        )
        .route(
            "/xotero/admin/groups/{id}",
            get(crate::handlers::groups::manage)
                .patch(crate::handlers::groups::manage)
                .delete(crate::handlers::groups::manage),
        )
        .route(
            "/xotero/groups/{id}/members/{userId}",
            put(crate::handlers::groups::manage).delete(crate::handlers::groups::manage),
        )
        .route(
            "/xotero/admin/groups/{id}/members/{userId}",
            put(crate::handlers::groups::manage).delete(crate::handlers::groups::manage),
        )
        .route(
            "/xotero/groups/{id}/owner",
            post(crate::handlers::groups::manage),
        )
        .route(
            "/xotero/admin/groups/{id}/owner",
            post(crate::handlers::groups::manage),
        )
        .route("/xotero/me/keys", get(manage).post(manage))
        .route("/xotero/me/keys/{id}", route_delete(manage))
        .route("/xotero/admin/users/{id}/keys", get(manage))
        .route(
            "/xotero/admin/users/{id}/keys/{keyId}",
            route_delete(manage),
        )
        .route(
            "/xotero/admin/users",
            get(crate::handlers::admin::users).post(crate::handlers::admin::users),
        )
        .route(
            "/xotero/admin/users/{id}",
            patch(crate::handlers::admin::users),
        )
        .route(
            "/xotero/admin/users/{id}/instance-admin",
            put(crate::handlers::admin::users),
        )
        .route(
            "/xotero/admin/users/{id}/identities",
            post(crate::handlers::admin::users).delete(crate::handlers::admin::users),
        )
        .route(
            "/xotero/web/session",
            get(crate::handlers::web_session::challenge).post(crate::handlers::web_session::login),
        )
        .route(
            "/xotero/web/session/logout",
            post(crate::handlers::web_session::logout),
        )
        .route("/keys/current", get(key_current).delete(manage))
        .route("/keys/sessions", post(create_session))
        .route(
            "/keys/sessions/{token}",
            get(check_session).delete(cancel_session),
        )
        .route("/login", get(login_page).post(login_authorize))
        .route("/users/{id}/groups", get(groups))
        .route("/groups/{id}", get(group_get).head(group_get))
        .route(
            "/groups/{id}/settings",
            get(settings_read)
                .post(settings_write)
                .delete(settings_delete),
        )
        .route("/groups/{id}/collections", objects("collection"))
        .route(
            "/groups/{id}/collections/{key}/items",
            get(collection_items),
        )
        .route(
            "/groups/{id}/collections/{key}/items/top",
            get(collection_items_top),
        )
        .route("/groups/{id}/searches", objects("search"))
        .route(
            "/groups/{id}/items",
            get(items_get)
                .post(
                    move |State(state): State<AppState>,
                          Extension(context): Extension<crate::domain::RequestContext>,
                          headers: HeaderMap,
                          body: Bytes| async move {
                        write(&state, &context, "item", headers, body).await
                    },
                )
                .patch(
                    move |State(state): State<AppState>,
                          Extension(context): Extension<crate::domain::RequestContext>,
                          headers: HeaderMap,
                          body: Bytes| async move {
                        write(&state, &context, "item", headers, body).await
                    },
                )
                .delete(
                    move |State(state): State<AppState>,
                          Extension(context): Extension<crate::domain::RequestContext>,
                          headers: HeaderMap,
                          Query(params): Query<HashMap<String, String>>| async move {
                        delete(&state, &context, "item", headers, params).await
                    },
                ),
        )
        .route("/groups/{id}/items/top", get(items_top))
        .route("/groups/{id}/items/trash", get(items_trash))
        .route("/groups/{id}/tags", get(tags_get).delete(tags_delete))
        .route(
            "/groups/{id}/fulltext",
            get(fulltext_versions).post(fulltext_write),
        )
        .route("/groups/{id}/items/{key}/fulltext", get(fulltext_item))
        .route(
            "/groups/{id}/items/{key}/file",
            get(file_get).post(file_post),
        )
        .route("/groups/{id}/deleted", get(deleted))
        .route(
            "/users/{id}/settings",
            get(settings_read)
                .post(settings_write)
                .delete(settings_delete),
        )
        .route("/users/{id}/collections", objects("collection"))
        // CLI listing of a collection's items, plus the top-level variant the
        // sync client fetches with format=keys when restoring a collection.
        .route("/users/{id}/collections/{key}/items", get(collection_items))
        .route(
            "/users/{id}/collections/{key}/items/top",
            get(collection_items_top),
        )
        .route("/users/{id}/searches", objects("search"))
        // Items share the write/delete logic but take a dedicated GET that adds
        // the CLI query API alongside the two sync reads.
        .route(
            "/users/{id}/items",
            get(items_get)
                .post(
                    move |State(state): State<AppState>,
                          Extension(context): Extension<crate::domain::RequestContext>,
                          headers: HeaderMap,
                          body: Bytes| async move {
                        write(&state, &context, "item", headers, body).await
                    },
                )
                .patch(
                    move |State(state): State<AppState>,
                          Extension(context): Extension<crate::domain::RequestContext>,
                          headers: HeaderMap,
                          body: Bytes| async move {
                        write(&state, &context, "item", headers, body).await
                    },
                )
                .delete(
                    move |State(state): State<AppState>,
                          Extension(context): Extension<crate::domain::RequestContext>,
                          headers: HeaderMap,
                          Query(p): Query<HashMap<String, String>>| async move {
                        delete(&state, &context, "item", headers, p).await
                    },
                ),
        )
        .route("/users/{id}/items/top", get(items_top))
        .route("/users/{id}/items/trash", get(items_trash))
        .route("/users/{id}/tags", get(tags_get).delete(tags_delete))
        .route(
            "/users/{id}/fulltext",
            get(fulltext_versions).post(fulltext_write),
        )
        .route("/users/{id}/items/{key}/fulltext", get(fulltext_item))
        .route(
            "/users/{id}/items/{key}/file",
            get(file_get).post(file_post),
        )
        .route("/uploads/{key}", post(upload_put))
        .route("/users/{id}/deleted", get(deleted))
        // Attachment uploads exceed the default 2 MiB extractor limit; raise it
        // to MAX_BODY; middleware and the capability handler enforce body bounds.
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), log_and_auth))
        .with_state(state)
}

#[cfg(test)]
mod body_tests {
    use super::*;
    use std::convert::Infallible;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use futures_util::stream;
    use tower::ServiceExt;

    fn test_router() -> Router {
        let storage_config = s3::Config {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            bucket: "test".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
            path_style: true,
            presign_ttl: 300,
        };
        let config = Config {
            web_origin: "https://library.example.test".into(),
            keys: HashMap::new(),
            login_kdf_key: vec![0; 32],
            user_id: crate::domain::UserId::new(1).unwrap(),
            username: "test".into(),
            display_name: "test".into(),
            bootstrap_instance_admin: false,
            library_id: crate::domain::LibraryId::new(1).unwrap(),
            bind: "127.0.0.1:8189".into(),
            public_url: "http://localhost:8189".into(),
            database_url: "postgres://localhost/test".into(),
            s3: storage_config.clone(),
            upload_concurrency: 4,
            upload_parts: 2,
            upload_max_bytes: 256 * 1024 * 1024,
            upload_timeout: Duration::from_secs(300),
        };
        router(AppState {
            config: Arc::new(config),
            pool: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/test")
                .unwrap(),
            storage: Arc::new(s3::Storage::new(&storage_config).unwrap()),
            uploads: Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }

    #[tokio::test]
    async fn missing_key_returns_forbidden_without_polling_incomplete_body() {
        // Given an incomplete application body that records every poll.
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&polls);
        let body = Body::from_stream(stream::poll_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Poll::<Option<Result<Bytes, Infallible>>>::Pending
        }));
        let request = Request::post("/users/1/items").body(body).unwrap();

        // When no API key was presented.
        let response = tokio::time::timeout(Duration::from_secs(2), test_router().oneshot(request))
            .await
            .expect("authorization waited for incomplete body")
            .unwrap();

        // Then authorization completes without asking the body for bytes.
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn public_prefix_lookalikes_require_authentication_before_body_poll() {
        for path in [
            "/uploadsuffix/token",
            "/keys/sessionssuffix",
            "/uploads/token/extra",
        ] {
            let polls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&polls);
            let body = Body::from_stream(stream::poll_fn(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                Poll::<Option<Result<Bytes, Infallible>>>::Pending
            }));
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                test_router().oneshot(Request::post(path).body(body).unwrap()),
            )
            .await
            .expect("lookalike route waited for body")
            .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
            assert_eq!(polls.load(Ordering::SeqCst), 0, "{path}");
        }
    }

    #[tokio::test]
    async fn corrupt_gzip_is_bad_request_instead_of_raw_fallback() {
        let request = Request::post("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("content-encoding", "gzip")
            .body(Body::from("not gzip"))
            .unwrap();
        let response = test_router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn truncated_gzip_is_bad_request_instead_of_raw_fallback() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"padding=data").unwrap();
        let mut gzip = encoder.finish().unwrap();
        gzip.truncate(gzip.len() - 4);
        let request = Request::post("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("content-encoding", "gzip")
            .body(Body::from(gzip))
            .unwrap();
        let response = test_router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn public_gzip_decoded_limit_plus_one_is_rejected() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&vec![b'x'; 1024 * 1024 + 1]).unwrap();
        let request = Request::get("/login")
            .header("content-encoding", "gzip")
            .body(Body::from(encoder.finish().unwrap()))
            .unwrap();
        let response = test_router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn public_encoded_limit_accepts_boundary_and_rejects_extra_byte() {
        for (size, encoding, expected) in [
            (1024 * 1024, "identity", StatusCode::FORBIDDEN),
            (1024 * 1024 + 1, "identity", StatusCode::PAYLOAD_TOO_LARGE),
            (1024 * 1024 + 1, "gzip", StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let request = Request::post("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("content-encoding", encoding)
                .body(Body::from(vec![b'x'; size]))
                .unwrap();
            let response = test_router().oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected, "{encoding} {size}");
        }
    }
}
