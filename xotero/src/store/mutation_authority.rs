use sha2::{Digest, Sha256};
use sqlx::PgConnection;

use crate::config::Config;
use crate::domain::{LibraryAccess, RequestContext};

/// Original server-authenticated coordinates, never authority cached across
/// body collection. Store callers pass this explicitly; no HTTP task-local is
/// consulted inside a transaction.
pub struct MutationProof<'a> {
    pub access: LibraryAccess,
    pub context: &'a RequestContext,
    pub config: &'a Config,
}

pub(super) async fn lock_mutation_authority(
    conn: &mut PgConnection,
    proof: &MutationProof<'_>,
) -> sqlx::Result<Option<LibraryAccess>> {
    let original = proof.context;
    let access = proof.access;
    let owner: Option<i64> = match access.group_id {
        Some(group) => {
            let owner = sqlx::query_scalar(
                "select owner_user_id from groups where id=$1 and library_id=$2",
            )
            .bind(group.get())
            .bind(access.library_id.get())
            .fetch_optional(&mut *conn)
            .await?;
            if owner.is_none() {
                return Ok(None);
            }
            owner
        }
        None => None,
    };
    let mut libraries = vec![original.principal.library_id.get(), access.library_id.get()];
    libraries.sort_unstable();
    libraries.dedup();
    for library in libraries {
        let query = if library == access.library_id.get() {
            "select id from library where id=$1 for update"
        } else {
            "select id from library where id=$1 for share"
        };
        if sqlx::query(query)
            .bind(library)
            .fetch_optional(&mut *conn)
            .await?
            .is_none()
        {
            return Ok(None);
        }
    }
    if let Some(group) = access.group_id {
        let locked: Option<i64> = sqlx::query_scalar(
            "select owner_user_id from groups where id=$1 and library_id=$2 for share",
        )
        .bind(group.get())
        .bind(access.library_id.get())
        .fetch_optional(&mut *conn)
        .await?;
        if locked != owner {
            return Ok(None);
        }
    }
    let mut users = vec![original.principal.user_id.get()];
    users.extend(owner);
    users.sort_unstable();
    users.dedup();
    let locked = sqlx::query("select id from users where id=any($1) order by id for share")
        .bind(&users)
        .fetch_all(&mut *conn)
        .await?;
    if locked.len() != users.len() {
        return Ok(None);
    }
    if sqlx::query(
        "select user_id from personal_libraries where user_id=$1 and library_id=$2 for share",
    )
    .bind(original.principal.user_id.get())
    .bind(original.principal.library_id.get())
    .fetch_optional(&mut *conn)
    .await?
    .is_none()
    {
        return Ok(None);
    }
    if let Some(key) = original.api_key_id {
        for query in [
            "select id from api_keys where id=$1 for share",
            "select api_key_id from api_key_user_permissions where api_key_id=$1 for share",
        ] {
            if sqlx::query(query)
                .bind(key.get())
                .fetch_optional(&mut *conn)
                .await?
                .is_none()
            {
                return Ok(None);
            }
        }
    }
    let mut grants = (false, false);
    if let Some(group) = access.group_id {
        if sqlx::query(
            "select user_id from group_memberships where group_id=$1 and user_id=$2 for share",
        )
        .bind(group.get())
        .bind(original.principal.user_id.get())
        .fetch_optional(&mut *conn)
        .await?
        .is_none()
        {
            return Ok(None);
        }
        if let Some(key) = original.api_key_id {
            grants.0 = sqlx::query(
                "select api_key_id from api_key_all_groups_permissions where api_key_id=$1 for share",
            )
            .bind(key.get()).fetch_optional(&mut *conn).await?.is_some();
            grants.1 = sqlx::query(
                "select api_key_id from api_key_group_permissions \
                 where api_key_id=$1 and group_id=$2 for share",
            )
            .bind(key.get())
            .bind(group.get())
            .fetch_optional(&mut *conn)
            .await?
            .is_some();
        }
    }
    // Recompute after the last wait, preserving every original association.
    // Optional grants contribute only if their positive row was locked.
    let hash = Sha256::digest(original.presented_key.as_bytes());
    let (principal, permissions) = match original.api_key_id {
        Some(key) => {
            let Some((current, principal, permissions)) =
                super::authenticate_api_key(&mut *conn, hash.as_slice()).await?
            else {
                return Ok(None);
            };
            if current != key {
                return Ok(None);
            }
            (principal, permissions)
        }
        None => {
            if original.principal.user_id != proof.config.user_id {
                return Ok(None);
            }
            let Some(permissions) = proof.config.recovery_permissions(hash.as_slice()) else {
                return Ok(None);
            };
            let Some(principal) =
                super::bootstrap_principal(&mut *conn, proof.config.user_id).await?
            else {
                return Ok(None);
            };
            (principal, permissions)
        }
    };
    if principal.user_id != original.principal.user_id
        || principal.library_id != original.principal.library_id
    {
        return Ok(None);
    }
    let current = match access.group_id {
        Some(group) => {
            match super::groups::resolve_group_library_with_grants(
                &mut *conn,
                group,
                principal.user_id,
                original.api_key_id,
                original.api_key_id.is_none().then_some(permissions),
                grants,
            )
            .await?
            {
                super::GroupLibraryResolution::Allowed(current) => current,
                super::GroupLibraryResolution::Missing | super::GroupLibraryResolution::Denied => {
                    return Ok(None);
                }
            }
        }
        None => LibraryAccess {
            library_id: principal.library_id,
            group_id: None,
            permissions,
            is_admin: true,
            file_write: permissions.write && permissions.files,
        },
    };
    Ok((current.library_id == access.library_id
        && current.permissions.library
        && current.permissions.write)
        .then_some(current))
}

pub(super) fn protected_setting(access: LibraryAccess, key: &str) -> bool {
    access.group_id.is_some()
        && !access.is_admin
        && matches!(
            key,
            "attachmentRenameTemplate" | "autoRenameFiles" | "autoRenameFilesFileTypes"
        )
}
