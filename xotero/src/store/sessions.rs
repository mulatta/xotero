use sqlx::{PgPool, Row};

use crate::domain::UserId;

use super::identity::principal_from_row;

pub enum LoginSession {
    Pending,
    Completed(crate::domain::Principal),
    Cancelled,
    Expired,
    Missing,
}

pub enum LoginSessionChange {
    Done,
    Conflict,
    Expired,
    Missing,
    UserUnavailable,
}

pub async fn create_login_session(
    pool: &PgPool,
    token_hash: &[u8],
    client_type: &str,
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    // Bound abandoned unauthenticated rows without shortening current sessions.
    sqlx::query(
        "delete from login_sessions \
         where (status = 'pending' and expires_at < now() - interval '1 day') \
            or (status = 'cancelled' and created_at < now() - interval '1 day')",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("insert into login_sessions (token_hash, client_type) values ($1, $2)")
        .bind(token_hash)
        .bind(client_type)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

pub async fn login_session(pool: &PgPool, token_hash: &[u8]) -> sqlx::Result<LoginSession> {
    let row = sqlx::query(
        "select ls.status, ls.expires_at <= now() as expired, \
                u.id as user_id, u.username, u.display_name, pl.library_id \
         from login_sessions ls \
         left join users u on u.id = ls.user_id \
         left join personal_libraries pl on pl.user_id = u.id \
         where ls.token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(LoginSession::Missing);
    };
    Ok(match row.get::<String, _>("status").as_str() {
        "pending" if row.get("expired") => LoginSession::Expired,
        "pending" => LoginSession::Pending,
        "cancelled" => LoginSession::Cancelled,
        "completed" => LoginSession::Completed(principal_from_row(&row)?),
        status => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid login session status {status}"
            )))
        }
    })
}

pub async fn cancel_login_session(
    pool: &PgPool,
    token_hash: &[u8],
) -> sqlx::Result<LoginSessionChange> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "select status, expires_at <= now() as expired \
         from login_sessions where token_hash = $1 for update",
    )
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let outcome = match row {
        None => LoginSessionChange::Missing,
        Some(row)
            if row.get::<String, _>("status") == "pending" && !row.get::<bool, _>("expired") =>
        {
            sqlx::query("update login_sessions set status = 'cancelled' where token_hash = $1")
                .bind(token_hash)
                .execute(&mut *tx)
                .await?;
            LoginSessionChange::Done
        }
        Some(_) => LoginSessionChange::Conflict,
    };
    tx.commit().await?;
    Ok(outcome)
}

pub async fn complete_login_session(
    pool: &PgPool,
    token_hash: &[u8],
    api_key_hash: &[u8],
    issuer: &str,
    subject: &str,
) -> sqlx::Result<LoginSessionChange> {
    let mut tx = pool.begin().await?;
    let session = sqlx::query(
        "select status, client_type, expires_at <= now() as expired \
         from login_sessions where token_hash = $1 for update",
    )
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(session) = session else {
        return Ok(LoginSessionChange::Missing);
    };
    if session.get::<String, _>("status") != "pending" {
        return Ok(LoginSessionChange::Conflict);
    }
    if session.get::<bool, _>("expired") {
        return Ok(LoginSessionChange::Expired);
    }
    // Discovery grants no authority. Separate statements establish the same
    // library -> user -> ownership -> identity order as authority mutations.
    let candidate = sqlx::query(
        "select u.id as user_id, pl.library_id \
         from external_identities e \
         join users u on u.id = e.user_id and u.disabled_at is null \
         join personal_libraries pl on pl.user_id = u.id \
         join library l on l.id = pl.library_id and l.kind = 'personal' \
         where e.issuer = $1 and e.subject = $2",
    )
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(candidate) = candidate else {
        return Ok(LoginSessionChange::UserUnavailable);
    };
    let mapped_user_id: i64 = candidate.get("user_id");
    let library_id: i64 = candidate.get("library_id");
    for (query, id) in [
        (
            "select id from library where id=$1 and kind='personal' for share",
            library_id,
        ),
        (
            "select id from users where id=$1 and disabled_at is null for share",
            mapped_user_id,
        ),
    ] {
        if sqlx::query(query)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .is_none()
        {
            return Ok(LoginSessionChange::UserUnavailable);
        }
    }
    if sqlx::query(
        "select user_id from personal_libraries \
         where user_id=$1 and library_id=$2 and library_kind='personal' for share",
    )
    .bind(mapped_user_id)
    .bind(library_id)
    .fetch_optional(&mut *tx)
    .await?
    .is_none()
    {
        return Ok(LoginSessionChange::UserUnavailable);
    }
    if sqlx::query(
        "select user_id from external_identities \
         where issuer=$1 and subject=$2 and user_id=$3 for share",
    )
    .bind(issuer)
    .bind(subject)
    .bind(mapped_user_id)
    .fetch_optional(&mut *tx)
    .await?
    .is_none()
    {
        return Ok(LoginSessionChange::UserUnavailable);
    }
    // Every positive row is now protected. Never chase a new owner/library
    // discovered after a wait: doing so would acquire an earlier lock late.
    let valid: bool = sqlx::query_scalar(
        "select exists(select 1 from users u \
         join personal_libraries p on p.user_id=u.id \
         join library l on l.id=p.library_id and l.kind=p.library_kind \
         join external_identities e on e.user_id=u.id \
         where u.id=$1 and u.disabled_at is null and p.library_id=$2 \
           and l.kind='personal' and e.issuer=$3 and e.subject=$4)",
    )
    .bind(mapped_user_id)
    .bind(library_id)
    .bind(issuer)
    .bind(subject)
    .fetch_one(&mut *tx)
    .await?;
    if !valid {
        return Ok(LoginSessionChange::UserUnavailable);
    }
    let user_id = UserId::new(mapped_user_id)
        .ok_or_else(|| sqlx::Error::Protocol(format!("invalid mapped user ID {mapped_user_id}")))?;
    let client_type: String = session.get("client_type");
    let key_name = match client_type.as_str() {
        "mac" => "Zotero for Mac",
        "windows" => "Zotero for Windows",
        "linux" => "Zotero for Linux",
        "ios" => "Zotero for iOS",
        "android" => "Zotero for Android",
        _ => "Zotero",
    };
    let api_key_id: i64 = sqlx::query_scalar(
        "insert into api_keys (user_id, name, token_hash) \
         values ($1, $2, $3) returning id",
    )
    .bind(user_id.get())
    .bind(key_name)
    .bind(api_key_hash)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "insert into api_key_user_permissions \
         (api_key_id, library, notes, write, files) \
         values ($1, true, true, true, true)",
    )
    .bind(api_key_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "insert into api_key_all_groups_permissions (api_key_id, library, write) \
         values ($1, true, true)",
    )
    .bind(api_key_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "update login_sessions \
         set status = 'completed', user_id = $2, api_key_id = $3, completed_at = now() \
         where token_hash = $1",
    )
    .bind(token_hash)
    .bind(user_id.get())
    .bind(api_key_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(LoginSessionChange::Done)
}
