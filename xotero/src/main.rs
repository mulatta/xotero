//! Self-hosted Zotero Web API v3 sync server.
//!
//! Objects are stored as opaque jsonb blobs in PostgreSQL (see `store`); each
//! write bumps a single library version counter so the client's `since` reads
//! and `If-Unmodified-Since-Version` writes stay coherent.

mod app;
mod config;
mod domain;
mod error;
mod handlers;
mod http;
mod metadata;
mod query;
mod s3;
mod store;
mod upload;

use crate::app::{router, AppState};
use crate::config::Config;
use std::sync::Arc;

use crate::handlers::files::{
    cleanup_pending_uploads, cleanup_retired_blobs, pending_upload_cleanup_loop,
};

pub(crate) fn upload_token() -> Option<String> {
    use std::io::Read;
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .ok()?;
    Some(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Debug, PartialEq)]
enum Command {
    Serve,
    Migrate,
    CollectGarbage,
}

fn parse_command(arguments: &[String]) -> Option<Command> {
    match arguments {
        [] => Some(Command::Serve),
        [migrate] if migrate == "migrate" => Some(Command::Migrate),
        [maintenance, gc, once]
            if maintenance == "maintenance" && gc == "gc" && once == "--once" =>
        {
            Some(Command::CollectGarbage)
        }
        _ => None,
    }
}

// --- library data -----------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = parse_command(&arguments) else {
        tracing::error!("usage: xotero [migrate | maintenance gc --once]");
        std::process::exit(2);
    };
    let config = Arc::new(Config::from_env());
    // Parse the embedded schema before serving so a bad pin fails at startup.
    std::sync::LazyLock::force(&metadata::SCHEMA);

    if command == Command::Migrate {
        // Schema step only, so operators can run it before the server starts:
        // no listener, bootstrap, blob reconciliation, upload reset, or storage.
        let pool = match sqlx::PgPool::connect(&config.database_url).await {
            Ok(pool) => pool,
            Err(error) => {
                tracing::error!(%error, "connect for migrations");
                std::process::exit(1);
            }
        };
        if let Err(error) = store::migrate(&pool).await {
            tracing::error!(%error, "apply migrations");
            std::process::exit(1);
        }
        tracing::info!("migrations applied");
        return;
    }

    if command == Command::CollectGarbage {
        // Maintenance runs beside the serving process: never migrate/bootstrap,
        // reset Uploading ownership, spawn cleanup loops, or open a listener.
        let pool = sqlx::PgPool::connect(&config.database_url)
            .await
            .expect("connect for blob collection");
        let storage = s3::Storage::new(&config.s3).expect("init object storage");
        match cleanup_retired_blobs(&pool, &storage, config.upload_timeout).await {
            Ok(true) => {}
            Ok(false) => std::process::exit(1),
            Err(error) => {
                tracing::error!(%error, "collect retired blobs");
                std::process::exit(1);
            }
        }
        return;
    }

    let pool = store::connect(&config.database_url)
        .await
        .expect("connect to database");
    let storage = Arc::new(s3::Storage::new(&config.s3).expect("init object storage"));
    if let Err(error) = store::reconcile_legacy_blobs(&pool, &storage, config.upload_timeout).await
    {
        tracing::error!(%error, "reconcile legacy blob pointers before serving");
        std::process::exit(1);
    }
    let bootstrap_oidc_issuer = std::env::var("XOTERO_BOOTSTRAP_OIDC_ISSUER").ok();
    let bootstrap_oidc_subject = std::env::var("XOTERO_BOOTSTRAP_OIDC_SUBJECT").ok();
    let external_identity = match (&bootstrap_oidc_issuer, &bootstrap_oidc_subject) {
        (Some(issuer), Some(subject))
            if !issuer.trim().is_empty() && !subject.trim().is_empty() =>
        {
            Some((issuer.as_str(), subject.as_str()))
        }
        (None, None) => None,
        _ => panic!("bootstrap OIDC issuer and subject must both be nonempty"),
    };
    store::bootstrap_identity(
        &pool,
        config.user_id,
        &config.username,
        &config.display_name,
        config.library_id,
        config.bootstrap_instance_admin,
        external_identity,
    )
    .await
    .expect("bootstrap identity");
    let state = AppState {
        uploads: Arc::new(tokio::sync::Semaphore::new(config.upload_concurrency)),
        config,
        pool,
        storage,
    };
    store::reset_interrupted_pending_uploads(&state.pool)
        .await
        .expect("recover interrupted uploads");
    cleanup_pending_uploads(&state).await;
    tokio::spawn(pending_upload_cleanup_loop(state.clone()));

    let listener = tokio::net::TcpListener::bind(&state.config.bind)
        .await
        .expect("bind address");
    tracing::info!(bind = %state.config.bind, "xotero listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server run");
}

#[cfg(test)]
mod command_tests {
    use super::{parse_command, Command};

    fn parse(arguments: &[&str]) -> Option<Command> {
        let arguments: Vec<String> = arguments.iter().map(|a| a.to_string()).collect();
        parse_command(&arguments)
    }

    #[test]
    fn no_arguments_serve() {
        assert_eq!(parse(&[]), Some(Command::Serve));
    }

    #[test]
    fn migrate_selects_migration_only() {
        assert_eq!(parse(&["migrate"]), Some(Command::Migrate));
    }

    #[test]
    fn maintenance_gc_once_collects_garbage() {
        assert_eq!(
            parse(&["maintenance", "gc", "--once"]),
            Some(Command::CollectGarbage)
        );
    }

    #[test]
    fn unknown_or_partial_commands_are_rejected() {
        for arguments in [
            &["migrate", "extra"][..],
            &["maintenance", "gc"],
            &["bogus"],
            &["--once"],
        ] {
            assert_eq!(parse(arguments), None, "{arguments:?}");
        }
    }
}

#[cfg(test)]
mod middleware_tests {
    use crate::http::validation::{
        is_attachment_permission_path, is_group_discovery_path, path_group_data_id,
    };

    #[test]
    fn attachment_permission_paths_match_exact_personal_and_group_routes() {
        for path in [
            "/users/101/items/ABCDEFGH/file",
            "/users/101/items/ABCDEFGH/file/view/url",
            "/groups/303/items/ABCDEFGH/file",
            "/groups/303/items/ABCDEFGH/file/view/url",
            "/groups/303/items/ABCDEFGI/file",
            "/users/101/items/OLDLIB22/file",
            "/users/101/items/LEGACY22/file",
            "/users/101/items/%4CEGACY22/file",
            "/groups/303/items/ABCDEFGO/file",
            "/groups/303/items/ABCDEFG0/file",
            "/groups/303/items/ABCDEFG1/file",
            "/groups/303/items/ABC/file",
            "/groups/303/items/abcdefgH/file",
            "/users/101/items/bad!/file",
        ] {
            assert!(is_attachment_permission_path(path), "{path}");
        }

        for path in [
            "/users/101/items/ABCDEFGH/filesuffix",
            "/users/101/items/ABCDEFGH/file/view",
            "/users/101/items/ABCDEFGH/file/view/url/extra",
            "/users/101/items/ABCDEFGH/file/",
            "/users/101/items/ABCDEFGH/file//view/url",
            "/users/101/items/ABCDEFGH//file",
            "/users/101/items//file",
            "/users/101//items/ABCDEFGH/file",
            "/users//items/ABCDEFGH/file",
            "//users/101/items/ABCDEFGH/file",
            "/users/0/items/ABCDEFGH/file",
            "/groups/-303/items/ABCDEFGH/file",
            "/groups/9223372036854775808/items/ABCDEFGH/file",
            "groups/303/items/ABCDEFGH/file",
        ] {
            assert!(!is_attachment_permission_path(path), "{path}");
        }
    }

    #[test]
    fn group_permission_bypass_is_limited_to_discovery_routes() {
        assert!(is_group_discovery_path("/groups/303"));
        assert!(is_group_discovery_path("/users/101/groups"));
        assert!(!is_group_discovery_path("/groups/303/items"));
        assert!(!is_group_discovery_path("/admin/users/101/groups"));
    }

    #[test]
    fn group_data_paths_resolve_only_nested_positive_ids() {
        assert_eq!(
            path_group_data_id("/groups/303/items")
                .unwrap()
                .map(|id| id.get()),
            Some(303)
        );
        assert_eq!(path_group_data_id("/groups/303").unwrap(), None);
        assert_eq!(path_group_data_id("/users/303/items").unwrap(), None);
        assert!(path_group_data_id("/groups/not-an-id/items").is_err());
        assert!(path_group_data_id("/groups/0/items").is_err());
    }
}
