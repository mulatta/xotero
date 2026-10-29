use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::domain::{ApiKeyId, LibraryId, Permissions, Principal, UserId};

pub(super) fn principal_from_row(row: &PgRow) -> sqlx::Result<Principal> {
    let raw_user_id = row.get::<i64, _>("user_id");
    let user_id = UserId::new(raw_user_id)
        .ok_or_else(|| sqlx::Error::Protocol(format!("invalid user ID {raw_user_id}")))?;
    let raw_library_id = row.get::<i64, _>("library_id");
    let library_id = LibraryId::new(raw_library_id)
        .ok_or_else(|| sqlx::Error::Protocol(format!("invalid library ID {raw_library_id}")))?;
    Ok(Principal {
        user_id,
        username: row.get("username"),
        display_name: row.get("display_name"),
        library_id,
    })
}

/// Initialize recovery ownership once, or explicitly bootstrap instance
/// authority once. Completion never depends on continued role/mapping existence.
pub async fn bootstrap_identity(
    pool: &PgPool,
    user_id: UserId,
    username: &str,
    display_name: &str,
    library_id: LibraryId,
    instance_admin: bool,
    external_identity: Option<(&str, &str)>,
) -> sqlx::Result<()> {
    use super::audit::{append, AuditOutcome, BootstrapAction};

    let mut tx = pool.begin().await?;
    sqlx::query("select xotero_lock_instance_authority()")
        .fetch_one(&mut *tx)
        .await?;
    let (marker, action) = if instance_admin {
        ("instance-admin", BootstrapAction::InstanceAdmin)
    } else {
        ("identity", BootstrapAction::Identity)
    };
    let complete: bool =
        sqlx::query_scalar("select exists(select 1 from bootstrap_state where name=$1)")
            .bind(marker)
            .fetch_one(&mut *tx)
            .await?;
    if complete {
        append(&mut tx, user_id, &action, AuditOutcome::Noop).await?;
        return tx.commit().await;
    }
    // Expected denials roll back just the proposed setup. Audit is deliberately
    // outside that savepoint and is committed even though startup fails closed.
    sqlx::query("savepoint bootstrap_setup")
        .execute(&mut *tx)
        .await?;
    let setup = bootstrap_setup(
        &mut tx,
        user_id,
        username,
        display_name,
        library_id,
        instance_admin,
        external_identity,
    )
    .await;
    match setup {
        Ok(()) => {
            sqlx::query("insert into bootstrap_state(name) values($1) on conflict do nothing")
                .bind("identity")
                .execute(&mut *tx)
                .await?;
            if instance_admin {
                sqlx::query("insert into bootstrap_state(name) values('instance-admin')")
                    .execute(&mut *tx)
                    .await?;
            }
            append(&mut tx, user_id, &action, AuditOutcome::Success).await?;
            tx.commit().await
        }
        Err(_) => {
            sqlx::query("rollback to savepoint bootstrap_setup")
                .execute(&mut *tx)
                .await?;
            append(&mut tx, user_id, &action, AuditOutcome::Denied).await?;
            tx.commit().await?;
            // SQL errors can include failing row values, including OIDC claims.
            // Only the sanitized outcome crosses the startup/logging boundary.
            Err(sqlx::Error::Protocol("bootstrap setup denied".into()))
        }
    }
}

async fn bootstrap_setup(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    username: &str,
    display_name: &str,
    library_id: LibraryId,
    instance_admin: bool,
    external_identity: Option<(&str, &str)>,
) -> sqlx::Result<()> {
    let initialized: bool =
        sqlx::query_scalar("select exists(select 1 from bootstrap_state where name='identity')")
            .fetch_one(&mut **tx)
            .await?;
    let library_kind: String =
        sqlx::query_scalar("select kind from library where id = $1 for share")
            .bind(library_id.get())
            .fetch_one(&mut **tx)
            .await?;
    if library_kind != "personal" {
        return Err(sqlx::Error::Protocol("bootstrap ownership conflict".into()));
    }
    if !initialized {
        sqlx::query(
            "insert into users (id, username, display_name) values ($1, $2, $3) \
             on conflict (id) do nothing",
        )
        .bind(user_id.get())
        .bind(username)
        .bind(display_name)
        .execute(&mut **tx)
        .await?;
    }
    let disabled: bool =
        sqlx::query_scalar("select disabled_at is not null from users where id=$1 for update")
            .bind(user_id.get())
            .fetch_one(&mut **tx)
            .await?;
    if instance_admin && disabled {
        return Err(sqlx::Error::Protocol("bootstrap user unavailable".into()));
    }
    if instance_admin {
        sqlx::query("insert into instance_admins(user_id) values($1) on conflict do nothing")
            .bind(user_id.get())
            .execute(&mut **tx)
            .await?;
    }
    if !initialized {
        sqlx::query(
            "insert into personal_libraries (user_id, library_id) values ($1, $2) \
             on conflict (user_id) do nothing",
        )
        .bind(user_id.get())
        .bind(library_id.get())
        .execute(&mut **tx)
        .await?;
    }
    let mapped_library_id: i64 =
        sqlx::query("select library_id from personal_libraries where user_id = $1 for update")
            .bind(user_id.get())
            .fetch_one(&mut **tx)
            .await?
            .get("library_id");
    if mapped_library_id != library_id.get() {
        return Err(sqlx::Error::Protocol("bootstrap ownership conflict".into()));
    }
    match external_identity {
        Some((issuer, subject)) => {
            sqlx::query(
                "insert into external_identities(issuer,subject,user_id) values($1,$2,$3) \
                 on conflict(issuer,subject) do nothing",
            )
            .bind(issuer)
            .bind(subject)
            .bind(user_id.get())
            .execute(&mut **tx)
            .await?;
            let mapped: i64 = sqlx::query_scalar(
                "select user_id from external_identities where issuer=$1 and subject=$2 for update",
            )
            .bind(issuer)
            .bind(subject)
            .fetch_one(&mut **tx)
            .await?;
            if mapped != user_id.get() {
                return Err(sqlx::Error::Protocol("bootstrap identity conflict".into()));
            }
        }
        None if instance_admin => {
            return Err(sqlx::Error::Protocol("bootstrap identity required".into()));
        }
        None => {}
    }
    if instance_admin {
        let reachable: bool = sqlx::query_scalar(
            "select exists(select 1 from xotero_reachable_admins() where user_id=$1)",
        )
        .bind(user_id.get())
        .fetch_one(&mut **tx)
        .await?;
        if !reachable {
            return Err(sqlx::Error::Protocol("bootstrap user unavailable".into()));
        }
    }

    // Explicit bootstrap IDs do not advance an identity sequence. Never move a
    // sequence backwards if higher generated IDs were later deleted.
    sqlx::query(
        "select setval( \
             pg_get_serial_sequence('users', 'id'), \
             greatest( \
                 (select coalesce(max(id), 1) from users), \
                 (select last_value from users_id_seq) \
             ), \
             true \
         )",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(())
}

/// Resolve the bootstrap principal on every static-key request so disabling the
/// user takes effect immediately.
pub async fn bootstrap_principal<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    user_id: UserId,
) -> sqlx::Result<Option<Principal>> {
    let row = sqlx::query(
        "select u.id as user_id, u.username, u.display_name, pl.library_id \
         from users u \
         join personal_libraries pl on pl.user_id = u.id \
         join library l on l.id = pl.library_id and l.kind = pl.library_kind \
         where u.id = $1 and u.disabled_at is null and l.kind = 'personal'",
    )
    .bind(user_id.get())
    .fetch_optional(executor)
    .await?;
    row.as_ref().map(principal_from_row).transpose()
}

/// Resolve a user-owned key from its SHA-256 digest. No positive result is
/// cached: revocation and user disablement apply on the next request.
pub async fn authenticate_api_key<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    token_hash: &[u8],
) -> sqlx::Result<Option<(ApiKeyId, Principal, Permissions)>> {
    let row = sqlx::query(
        "select k.id as api_key_id, u.id as user_id, u.username, u.display_name, pl.library_id, \
                p.library, p.notes, p.write, p.files \
         from api_keys k \
         join users u on u.id = k.user_id \
         join personal_libraries pl on pl.user_id = u.id \
         join library l on l.id = pl.library_id and l.kind = pl.library_kind \
         join api_key_user_permissions p on p.api_key_id = k.id \
         where k.token_hash = $1 and k.revoked_at is null \
           and u.disabled_at is null and l.kind = 'personal'",
    )
    .bind(token_hash)
    .fetch_optional(executor)
    .await?;
    row.as_ref()
        .map(|row| {
            let raw_api_key_id = row.get::<i64, _>("api_key_id");
            let api_key_id = ApiKeyId::new(raw_api_key_id).ok_or_else(|| {
                sqlx::Error::Protocol(format!("invalid API key ID {raw_api_key_id}"))
            })?;
            Ok((
                api_key_id,
                principal_from_row(row)?,
                Permissions {
                    library: row.get("library"),
                    notes: row.get("notes"),
                    write: row.get("write"),
                    files: row.get("files"),
                },
            ))
        })
        .transpose()
}
