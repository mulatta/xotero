//! PostgreSQL-backed library storage.
//!
//! Objects are stored as opaque jsonb blobs keyed by (kind, key). Every write
//! bumps the single library version counter inside a transaction and stamps the
//! affected rows with the new version, so the client's `since` reads and
//! `If-Unmodified-Since-Version` writes stay coherent.

use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::domain::LibraryId;

mod files;
mod fulltext;
mod groups;
mod identity;
mod objects;
mod sessions;
mod settings;
mod tags;
mod versions;
pub use files::{
    claim_pending_upload, claim_pending_upload_garbage, create_pending_upload,
    delete_pending_upload_garbage, discard_pending_upload, file_meta, mark_pending_upload_uploaded,
    pending_upload, pending_upload_cleanup_cutoff, register_file,
    reset_interrupted_pending_uploads, reset_pending_upload, stored_file_attachment_exists,
    FileRegistrationOutcome, PendingUpload, PendingUploadState,
};
pub use fulltext::{fulltext_item, fulltext_versions, write_fulltext};
pub use groups::{
    active_user_exists, api_key_group_grants, group_for_user, groups_for_user,
    resolve_group_library, GroupGrant, GroupLibraryResolution, GroupMetadata,
};
pub use identity::{
    authenticate_api_key, bootstrap_external_identity, bootstrap_identity, bootstrap_principal,
};
pub use objects::{delete, item_keys, objects, query_items, write, ObjectMutation};
pub use sessions::{
    cancel_login_session, complete_login_session, create_login_session, login_session,
    LoginSession, LoginSessionChange,
};
pub use settings::{delete_settings, settings, write_settings};
pub use tags::{delete_tags, tags};
pub(super) use versions::version_map;
pub use versions::{current_version, deleted, top_versions, versions};

pub enum Outcome<T> {
    Done(T),
    Conflict(i64),
}

fn is_stored_file_attachment(value: &Value) -> bool {
    value.get("itemType").and_then(Value::as_str) == Some("attachment")
        && matches!(
            value.get("linkMode").and_then(Value::as_str),
            Some("imported_file" | "imported_url")
        )
}

/// Lock the library row, check the client's expected version, and reserve the
/// next one. Serializing on the row also prevents concurrent writes from racing.
pub(super) async fn guarded_version(
    conn: &mut sqlx::PgConnection,
    library_id: LibraryId,
    expected: Option<i64>,
) -> sqlx::Result<Outcome<i64>> {
    let current: i64 = sqlx::query("select version from library where id = $1 for update")
        .bind(library_id.get())
        .fetch_one(&mut *conn)
        .await?
        .get("version");
    if matches!(expected, Some(v) if v != current) {
        return Ok(Outcome::Conflict(current));
    }
    let version = current + 1;
    sqlx::query("update library set version = $2 where id = $1")
        .bind(library_id.get())
        .bind(version)
        .execute(&mut *conn)
        .await?;
    Ok(Outcome::Done(version))
}

pub async fn connect(url: &str) -> sqlx::Result<PgPool> {
    let pool = PgPool::connect(url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// A write that changes nothing (empty batch / no matching keys): report the
/// current version, or a conflict if the client's expectation is already stale,
/// without bumping the version — a no-op must not churn the counter and make
/// every other client think the library changed.
pub(super) async fn no_change(
    pool: &PgPool,
    library_id: LibraryId,
    expected: Option<i64>,
) -> sqlx::Result<Outcome<i64>> {
    let current = current_version(pool, library_id).await?;
    Ok(match expected {
        Some(v) if v != current => Outcome::Conflict(current),
        _ => Outcome::Done(current),
    })
}
