use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::config::Config;
use crate::domain::{
    ApiKeyId, GroupId, LibraryAccess, LibraryId, Permissions, Principal, RequestContext, UserId,
};

use super::is_stored_file_attachment;

pub struct FileMeta {
    pub md5: String,
    pub blob_md5: String,
    pub mtime: i64,
    pub filesize: i64,
    pub compressed: bool,
    pub blob_key: String,
}

/// Client-visible metadata and immutable object pointer for an attachment file.
pub async fn file_meta(
    pool: &PgPool,
    library_id: LibraryId,
    item_key: &str,
) -> sqlx::Result<Option<FileMeta>> {
    let row = sqlx::query(
        "select f.md5, f.blob_md5, f.mtime, f.filesize, f.compressed, f.blob_key \
         from file f \
         join object o on o.library_id = f.library_id \
             and o.kind = 'item' \
             and o.key = f.item_key \
             and o.data->>'itemType' = 'attachment' \
             and o.data->>'linkMode' in ('imported_file', 'imported_url') \
         where f.library_id = $1 and f.item_key = $2",
    )
    .bind(library_id.get())
    .bind(item_key)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| FileMeta {
        md5: r.get("md5"),
        blob_md5: r.get("blob_md5"),
        mtime: r.get("mtime"),
        filesize: r.get("filesize"),
        compressed: r.get("compressed"),
        blob_key: r.get("blob_key"),
    }))
}

pub async fn stored_file_attachment_exists(
    pool: &PgPool,
    library_id: LibraryId,
    item_key: &str,
) -> sqlx::Result<bool> {
    let data: Option<Value> = sqlx::query_scalar(
        "select data from object where library_id = $1 and kind = 'item' and key = $2",
    )
    .bind(library_id.get())
    .bind(item_key)
    .fetch_optional(pool)
    .await?;
    Ok(data.as_ref().is_some_and(is_stored_file_attachment))
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PendingUploadState {
    Authorized,
    Uploading,
    Uploaded,
    Discarded,
    Deleting,
}

#[derive(Clone)]
pub struct PendingUpload {
    pub library_id: LibraryId,
    pub group_id: Option<GroupId>,
    pub authorizer_key_hash: Vec<u8>,
    pub bootstrap_user_id: Option<UserId>,
    pub item_key: String,
    pub expected_md5: Option<String>,
    pub blob_key: String,
    pub md5: String,
    pub upload_md5: String,
    pub filename: String,
    pub filesize: i64,
    pub mtime: i64,
    pub compressed: bool,
    pub state: PendingUploadState,
}

struct UploadAuthority {
    api_key_id: Option<ApiKeyId>,
    principal: Principal,
    permissions: Permissions,
}

impl UploadAuthority {
    async fn resolve(
        conn: &mut sqlx::PgConnection,
        config: &Config,
        key_hash: &[u8],
        bootstrap_user_id: Option<UserId>,
    ) -> sqlx::Result<Option<Self>> {
        match bootstrap_user_id {
            Some(user_id) => {
                if user_id != config.user_id {
                    return Ok(None);
                }
                let Some(permissions) = config.recovery_permissions(key_hash) else {
                    return Ok(None);
                };
                Ok(super::bootstrap_principal(conn, user_id)
                    .await?
                    .map(|principal| Self {
                        api_key_id: None,
                        principal,
                        permissions,
                    }))
            }
            None => Ok(super::authenticate_api_key(conn, key_hash).await?.map(
                |(api_key_id, principal, permissions)| Self {
                    api_key_id: Some(api_key_id),
                    principal,
                    permissions,
                },
            )),
        }
    }

    async fn allows(
        &self,
        conn: &mut sqlx::PgConnection,
        upload: &PendingUpload,
        grant_rows: (bool, bool),
    ) -> sqlx::Result<bool> {
        let Some(group_id) = upload.group_id else {
            return Ok(self.principal.library_id == upload.library_id
                && self.permissions.library
                && self.permissions.write
                && self.permissions.files);
        };
        match super::groups::resolve_group_library_with_grants(
            conn,
            group_id,
            self.principal.user_id,
            self.api_key_id,
            self.api_key_id.is_none().then_some(self.permissions),
            grant_rows,
        )
        .await?
        {
            super::GroupLibraryResolution::Allowed(access) => {
                Ok(access.library_id == upload.library_id && access.file_write)
            }
            super::GroupLibraryResolution::Denied | super::GroupLibraryResolution::Missing => {
                Ok(false)
            }
        }
    }
}

impl PendingUpload {
    pub(crate) async fn authorized(&self, pool: &PgPool, config: &Config) -> sqlx::Result<bool> {
        let mut conn = pool.acquire().await?;
        let Some(authority) = UploadAuthority::resolve(
            &mut conn,
            config,
            &self.authorizer_key_hash,
            self.bootstrap_user_id,
        )
        .await?
        else {
            return Ok(false);
        };
        authority.allows(&mut conn, self, (true, true)).await
    }
}

/// Discovery supplies lock candidates only. Rebinding discovered identities
/// fails closed rather than acquiring an earlier library lock out of order.
async fn lock_upload_authorities(
    conn: &mut sqlx::PgConnection,
    upload: &PendingUpload,
    context: &RequestContext,
    config: &Config,
) -> sqlx::Result<Option<i64>> {
    let caller_hash = Sha256::digest(context.presented_key.as_bytes());
    let credentials = [
        (
            upload.authorizer_key_hash.as_slice(),
            upload.bootstrap_user_id,
        ),
        (
            caller_hash.as_slice(),
            context
                .api_key_id
                .is_none()
                .then_some(context.principal.user_id),
        ),
    ];
    let mut authorities = Vec::with_capacity(2);
    for (hash, bootstrap_user_id) in credentials {
        let Some(authority) =
            UploadAuthority::resolve(&mut *conn, config, hash, bootstrap_user_id).await?
        else {
            return Ok(None);
        };
        authorities.push(authority);
    }
    let mut libraries = vec![upload.library_id.get()];
    let mut users = Vec::new();
    let mut keys = Vec::new();
    for authority in &authorities {
        libraries.push(authority.principal.library_id.get());
        users.push(authority.principal.user_id.get());
        if let Some(key) = authority.api_key_id {
            keys.push(key.get());
        }
    }
    libraries.sort_unstable();
    libraries.dedup();
    let mut current_version = None;
    for library in libraries {
        let query = if library == upload.library_id.get() {
            "select version from library where id = $1 for update"
        } else {
            "select version from library where id = $1 for share"
        };
        let version: Option<i64> = sqlx::query_scalar(query)
            .bind(library)
            .fetch_optional(&mut *conn)
            .await?;
        let Some(version) = version else {
            return Ok(None);
        };
        if library == upload.library_id.get() {
            current_version = Some(version);
        }
    }
    if let Some(group) = upload.group_id {
        let owner: Option<i64> = sqlx::query_scalar(
            "select owner_user_id from groups where id = $1 and library_id = $2 for share",
        )
        .bind(group.get())
        .bind(upload.library_id.get())
        .fetch_optional(&mut *conn)
        .await?;
        let Some(owner) = owner else {
            return Ok(None);
        };
        users.push(owner);
    }
    users.sort_unstable();
    users.dedup();
    sqlx::query("select id from users where id = any($1) order by id for share")
        .bind(&users)
        .fetch_all(&mut *conn)
        .await?;
    // Only the two credential owners need personal ownership mappings.
    let mut owners: Vec<i64> = authorities
        .iter()
        .map(|authority| authority.principal.user_id.get())
        .collect();
    owners.sort_unstable();
    owners.dedup();
    let mappings = sqlx::query(
        "select user_id from personal_libraries \
         where user_id = any($1) order by user_id for share",
    )
    .bind(&owners)
    .fetch_all(&mut *conn)
    .await?;
    if mappings.len() != owners.len() {
        return Ok(None);
    }
    keys.sort_unstable();
    keys.dedup();
    for query in [
        "select id from api_keys where id = any($1) order by id for share",
        "select api_key_id from api_key_user_permissions \
         where api_key_id = any($1) order by api_key_id for share",
    ] {
        let rows = sqlx::query(query).bind(&keys).fetch_all(&mut *conn).await?;
        if rows.len() != keys.len() {
            return Ok(None);
        }
    }
    let mut all_grants: Vec<i64> = Vec::new();
    let mut explicit_grants: Vec<i64> = Vec::new();
    if let Some(group) = upload.group_id {
        let memberships = sqlx::query(
            "select user_id from group_memberships \
             where group_id = $1 and user_id = any($2) order by user_id for share",
        )
        .bind(group.get())
        .bind(&owners)
        .fetch_all(&mut *conn)
        .await?;
        if memberships.len() != owners.len() {
            return Ok(None);
        }
        all_grants = sqlx::query_scalar(
            "select api_key_id from api_key_all_groups_permissions \
             where api_key_id = any($1) order by api_key_id for share",
        )
        .bind(&keys)
        .fetch_all(&mut *conn)
        .await?;
        explicit_grants = sqlx::query_scalar(
            "select api_key_id from api_key_group_permissions \
             where group_id = $1 and api_key_id = any($2) order by api_key_id for share",
        )
        .bind(group.get())
        .bind(&keys)
        .fetch_all(&mut *conn)
        .await?;
    }
    // Re-read after all waits. Missing optional grants must not become new,
    // unlocked positive evidence if a concurrent transaction inserts them.
    for ((hash, bootstrap_user_id), discovered) in credentials.into_iter().zip(authorities) {
        let Some(current) =
            UploadAuthority::resolve(&mut *conn, config, hash, bootstrap_user_id).await?
        else {
            return Ok(None);
        };
        if current.api_key_id != discovered.api_key_id
            || current.principal.user_id != discovered.principal.user_id
            || current.principal.library_id != discovered.principal.library_id
        {
            return Ok(None);
        }
        let grant_rows = (
            current
                .api_key_id
                .is_some_and(|id| all_grants.contains(&id.get())),
            current
                .api_key_id
                .is_some_and(|id| explicit_grants.contains(&id.get())),
        );
        if !current.allows(&mut *conn, upload, grant_rows).await? {
            return Ok(None);
        }
    }
    Ok(current_version)
}

const PENDING_UPLOAD_COLUMNS: &str = "\
    library_id, group_id, authorizer_key_hash, bootstrap_user_id, \
    item_key, expected_md5, blob_key, md5, upload_md5, filename, filesize, \
    mtime, compressed, state";

fn pending_upload_from_row(row: PgRow) -> PendingUpload {
    let bootstrap_user_id = row
        .get::<Option<i64>, _>("bootstrap_user_id")
        .map(|id| UserId::new(id).expect("pending upload user IDs are positive"));
    PendingUpload {
        library_id: LibraryId::new(row.get("library_id"))
            .expect("pending upload library IDs are positive"),
        group_id: row
            .get::<Option<i64>, _>("group_id")
            .map(|id| GroupId::new(id).expect("pending upload group IDs are positive")),
        authorizer_key_hash: row.get("authorizer_key_hash"),
        bootstrap_user_id,
        item_key: row.get("item_key"),
        expected_md5: row.get("expected_md5"),
        blob_key: row.get("blob_key"),
        md5: row.get("md5"),
        upload_md5: row.get("upload_md5"),
        filename: row.get("filename"),
        filesize: row.get("filesize"),
        mtime: row.get("mtime"),
        compressed: row.get("compressed"),
        state: match row.get::<String, _>("state").as_str() {
            "authorized" => PendingUploadState::Authorized,
            "uploading" => PendingUploadState::Uploading,
            "uploaded" => PendingUploadState::Uploaded,
            "discarded" => PendingUploadState::Discarded,
            "deleting" => PendingUploadState::Deleting,
            _ => unreachable!("pending upload state constraint"),
        },
    }
}

pub async fn create_pending_upload(
    pool: &PgPool,
    token_hash: &[u8],
    upload: &PendingUpload,
) -> sqlx::Result<()> {
    sqlx::query(
        "insert into pending_uploads ( \
             token_hash, library_id, group_id, authorizer_key_hash, bootstrap_user_id, \
             item_key, expected_md5, blob_key, md5, upload_md5, filename, \
             filesize, mtime, compressed, state \
         ) values ( \
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
             'authorized' \
         )",
    )
    .bind(token_hash)
    .bind(upload.library_id.get())
    .bind(upload.group_id.map(GroupId::get))
    .bind(&upload.authorizer_key_hash)
    .bind(upload.bootstrap_user_id.map(UserId::get))
    .bind(&upload.item_key)
    .bind(&upload.expected_md5)
    .bind(&upload.blob_key)
    .bind(&upload.md5)
    .bind(&upload.upload_md5)
    .bind(&upload.filename)
    .bind(upload.filesize)
    .bind(upload.mtime)
    .bind(upload.compressed)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn pending_upload(
    pool: &PgPool,
    token_hash: &[u8],
) -> sqlx::Result<Option<PendingUpload>> {
    let query = format!(
        "select {PENDING_UPLOAD_COLUMNS} \
         from pending_uploads where token_hash = $1 and expires_at > now()"
    );
    let row = sqlx::query(&query)
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(pending_upload_from_row))
}

pub async fn claim_pending_upload(pool: &PgPool, token_hash: &[u8]) -> sqlx::Result<bool> {
    let changed = sqlx::query(
        "update pending_uploads set state = 'uploading' \
         where token_hash = $1 and state = 'authorized' and expires_at > now()",
    )
    .bind(token_hash)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(changed == 1)
}

pub async fn reset_pending_upload(pool: &PgPool, token_hash: &[u8]) -> sqlx::Result<()> {
    sqlx::query(
        "update pending_uploads \
         set state = case when expires_at > now() then 'authorized' else 'discarded' end \
         where token_hash = $1 and state = 'uploading'",
    )
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn discard_pending_upload(
    pool: &PgPool,
    token_hash: &[u8],
    uncertain: bool,
) -> sqlx::Result<()> {
    sqlx::query(
        "update pending_uploads set state = 'discarded', gc_attempted_at = null, \
             expires_at = case when $2 then 'infinity'::timestamptz else expires_at end \
         where token_hash = $1 and state = 'uploading'",
    )
    .bind(token_hash)
    .bind(uncertain)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_pending_upload_uploaded(
    pool: &PgPool,
    token_hash: &[u8],
    deadline: tokio::time::Instant,
    cancelled: impl std::future::Future<Output = ()>,
) -> sqlx::Result<bool> {
    let prepare = async {
        let mut tx = pool.begin().await?;
        sqlx::query("select token_hash from pending_uploads where token_hash = $1 for update")
            .bind(token_hash)
            .fetch_optional(&mut *tx)
            .await?;
        let changed = sqlx::query(
            "update pending_uploads set state = 'uploaded' \
             where token_hash = $1 and state = 'uploading' and expires_at > clock_timestamp()",
        )
        .bind(token_hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        Ok::<_, sqlx::Error>((tx, changed == 1))
    };
    // Dropping preparation rolls back, including a row-lock wait. Cancellation
    // cannot interrupt COMMIT: a lost acknowledgement is an unknown outcome,
    // never authority to compensate a possibly published candidate.
    let (tx, changed) = tokio::select! {
        biased;
        _ = cancelled => return Ok(false),
        _ = tokio::time::sleep_until(deadline) => return Ok(false),
        result = prepare => result?,
    };
    if tokio::time::Instant::now() >= deadline {
        return Ok(false);
    }
    tx.commit().await?;
    Ok(changed)
}

pub async fn reset_interrupted_pending_uploads(pool: &PgPool) -> sqlx::Result<()> {
    // Infinite expiry is a non-purgeable cleanup identity, never a live token:
    // Discarded/Deleting cannot publish. Remote initiation may finish after a
    // canceled request's first empty listing, so uncertain identities survive.
    sqlx::query(
        "update pending_uploads set state = 'discarded', expires_at = 'infinity', \
             gc_attempted_at = null \
         where state = 'uploading' or expires_at = 'infinity'::timestamptz",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub struct PendingUploadGarbage {
    pub token_hash: Vec<u8>,
    pub blob_key: String,
}

pub async fn pending_upload_cleanup_cutoff(pool: &PgPool) -> sqlx::Result<String> {
    sqlx::query_scalar("select clock_timestamp()::text")
        .fetch_one(pool)
        .await
}

pub async fn claim_pending_upload_garbage(
    pool: &PgPool,
    limit: i64,
    cutoff: &str,
) -> sqlx::Result<Vec<PendingUploadGarbage>> {
    // Retained identities recur, but a pass must not revisit its own attempts.
    // The global fence also covers expired registration changing Deleting to
    // Discarded; monotonic attempts preserve it across overlapping passes.
    let rows = sqlx::query(
        "with candidates as ( \
             select token_hash from pending_uploads \
             where created_at <= $2::text::timestamptz \
               and (gc_attempted_at is null or gc_attempted_at < $2::text::timestamptz) \
               and ((state = 'discarded' and (expires_at <> 'infinity'::timestamptz \
                    or gc_attempted_at is null \
                    or gc_attempted_at < $2::text::timestamptz - interval '1 minute')) \
                or (expires_at <= $2::text::timestamptz and state not in ('uploading', 'deleting')) \
                or (state = 'deleting' \
                    and coalesce(gc_attempted_at, '-infinity') \
                        < $2::text::timestamptz - interval '1 minute')) \
             order by coalesce(gc_attempted_at, created_at), token_hash \
             limit $1 for update skip locked \
         ) \
         update pending_uploads p set state = 'deleting', \
             gc_attempted_at = greatest(p.gc_attempted_at, clock_timestamp(), $2::text::timestamptz) \
         from candidates c where p.token_hash = c.token_hash \
         returning p.token_hash, p.blob_key",
    )
    .bind(limit)
    .bind(cutoff)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PendingUploadGarbage {
            token_hash: row.get("token_hash"),
            blob_key: row.get("blob_key"),
        })
        .collect())
}

pub async fn delete_pending_upload_garbage(pool: &PgPool, token_hash: &[u8]) -> sqlx::Result<()> {
    sqlx::query(
        "with removed as ( \
             delete from pending_uploads where token_hash = $1 and state = 'deleting' \
                 and expires_at <> 'infinity'::timestamptz \
         ) \
         update pending_uploads set state = 'discarded', \
             gc_attempted_at = greatest(gc_attempted_at, clock_timestamp()) \
         where token_hash = $1 and state = 'deleting' \
             and expires_at = 'infinity'::timestamptz",
    )
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub enum FileRegistrationOutcome {
    Done(i64),
    Conflict(i64),
    InvalidItem,
    InvalidUpload,
    Denied,
}

/// Atomically make one immutable candidate the registered attachment and consume
/// its capability. Library serialization makes the file compare-and-swap safe
/// for both existing rows and concurrent first uploads.
pub async fn register_file(
    pool: &PgPool,
    token_hash: &[u8],
    item_key: &str,
    access: LibraryAccess,
    context: &RequestContext,
    config: &Config,
) -> sqlx::Result<FileRegistrationOutcome> {
    let library_id = access.library_id;
    let mut tx = pool.begin().await?;
    let query = format!(
        "select {PENDING_UPLOAD_COLUMNS}, expires_at > now() as valid \
         from pending_uploads where token_hash = $1 for update"
    );
    let pending = sqlx::query(&query)
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(pending) = pending else {
        return Ok(FileRegistrationOutcome::InvalidUpload);
    };
    let valid = pending.get::<bool, _>("valid");
    let upload = pending_upload_from_row(pending);
    if !valid {
        sqlx::query("update pending_uploads set state = 'discarded' where token_hash = $1")
            .bind(token_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(FileRegistrationOutcome::InvalidUpload);
    }
    if upload.state != PendingUploadState::Uploaded
        || upload.library_id != library_id
        || upload.group_id != access.group_id
        || upload.item_key != item_key
    {
        return Ok(FileRegistrationOutcome::InvalidUpload);
    }

    let Some(current_version) = lock_upload_authorities(&mut tx, &upload, context, config).await?
    else {
        return Ok(FileRegistrationOutcome::Denied);
    };
    let item: Option<Value> = sqlx::query_scalar(
        "select data from object \
         where library_id = $1 and kind = 'item' and key = $2 for update",
    )
    .bind(library_id.get())
    .bind(item_key)
    .fetch_optional(&mut *tx)
    .await?;
    if item
        .as_ref()
        .is_none_or(|data| !is_stored_file_attachment(data))
    {
        sqlx::query("update pending_uploads set state = 'discarded' where token_hash = $1")
            .bind(token_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(FileRegistrationOutcome::InvalidItem);
    }
    let current_md5 = sqlx::query_scalar::<_, String>(
        "select md5 from file where library_id = $1 and item_key = $2",
    )
    .bind(library_id.get())
    .bind(item_key)
    .fetch_optional(&mut *tx)
    .await?;
    let precondition_matches = match (upload.expected_md5.as_deref(), current_md5.as_deref()) {
        (None, None) => true,
        (Some(expected), Some(current)) => expected.eq_ignore_ascii_case(current),
        _ => false,
    };
    if !precondition_matches {
        sqlx::query("update pending_uploads set state = 'discarded' where token_hash = $1")
            .bind(token_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(FileRegistrationOutcome::Conflict(current_version));
    }
    let version = current_version + 1;
    sqlx::query("update library set version = $2 where id = $1")
        .bind(library_id.get())
        .bind(version)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "insert into file \
         (library_id, item_key, blob_key, md5, blob_md5, filename, filesize, mtime, \
          compressed, version) \
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         on conflict (library_id, item_key) \
         do update set blob_key = $3, md5 = $4, blob_md5 = $5, filename = $6, \
                       filesize = $7, mtime = $8, compressed = $9, version = $10",
    )
    .bind(library_id.get())
    .bind(item_key)
    .bind(&upload.blob_key)
    .bind(&upload.md5)
    .bind(&upload.upload_md5)
    .bind(&upload.filename)
    .bind(upload.filesize)
    .bind(upload.mtime)
    .bind(upload.compressed)
    .bind(version)
    .execute(&mut *tx)
    .await?;
    // Real Zotero stamps original-file metadata onto the attachment item when
    // registering a ZIP. Clients use filename to select its primary ZIP entry.
    sqlx::query(
        "update object set version = $3, \
         data = data || jsonb_build_object( \
             'md5', $4::text, 'mtime', $5::bigint, 'filename', $6::text, 'version', $3) \
         where library_id = $1 and kind = 'item' and key = $2",
    )
    .bind(library_id.get())
    .bind(item_key)
    .bind(version)
    .bind(&upload.md5)
    .bind(upload.mtime)
    .bind(&upload.filename)
    .execute(&mut *tx)
    .await?;
    sqlx::query("delete from pending_uploads where token_hash = $1")
        .bind(token_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(FileRegistrationOutcome::Done(version))
}
