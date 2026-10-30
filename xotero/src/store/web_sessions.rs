use sqlx::{PgConnection, PgPool, Row};

use super::audit::append_web;
pub use super::audit::WebSessionAction;

pub async fn deny_web_session(pool: &PgPool, action: WebSessionAction) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    append_web(&mut tx, action, None).await?;
    tx.commit().await
}

async fn denied(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    action: WebSessionAction,
) -> sqlx::Result<()> {
    append_web(&mut tx, action, None).await?;
    tx.commit().await
}

/// All Web operations first take this browser-family pending lock, then challenge
/// rows, sorted libraries, users, ownership, exact identities, keys and sessions.
/// Authority mutations do not acquire the pending lock or challenge rows.
async fn lock_browser(conn: &mut PgConnection, browser: &[u8; 32]) -> sqlx::Result<()> {
    let family = i32::from_be_bytes([browser[0], browser[1], browser[2], browser[3]]);
    sqlx::query("select pg_advisory_xact_lock(146415674, $1)")
        .bind(family)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn create_web_challenge(
    pool: &PgPool,
    browser: &[u8; 32],
    csrf: &[u8; 32],
    origin: &str,
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    lock_browser(&mut tx, browser).await?;
    sqlx::query(
        "delete from web_challenges where browser_hash=$1 and expires_at<=clock_timestamp()",
    )
    .bind(browser.as_slice())
    .execute(&mut *tx)
    .await?;
    sqlx::query("insert into web_challenges(token_hash,browser_hash,origin) values($1,$2,$3)")
        .bind(csrf.as_slice())
        .bind(browser.as_slice())
        .bind(origin)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

struct Binding {
    user: i64,
    library: i64,
    issuer: String,
    subject: String,
}

impl Binding {
    fn from_row(row: &sqlx::postgres::PgRow) -> Self {
        Self {
            user: row.get("user_id"),
            library: row.get("library_id"),
            issuer: row.get("issuer"),
            subject: row.get("subject"),
        }
    }
}

/// Discovery never authorizes. Never follow a changed mapping after a wait:
/// doing so could request an earlier authority row while holding a later one.
async fn lock_bindings(conn: &mut PgConnection, bindings: &[Binding]) -> sqlx::Result<()> {
    for (query, mut ids) in [
        (
            "select id from library where id=any($1) order by id for share",
            bindings.iter().map(|b| b.library).collect::<Vec<_>>(),
        ),
        (
            "select id from users where id=any($1) order by id for share",
            bindings.iter().map(|b| b.user).collect::<Vec<_>>(),
        ),
        (
            "select user_id from personal_libraries where user_id=any($1) \
             order by user_id for share",
            bindings.iter().map(|b| b.user).collect::<Vec<_>>(),
        ),
    ] {
        ids.sort_unstable();
        ids.dedup();
        sqlx::query(query).bind(ids).fetch_all(&mut *conn).await?;
    }
    let mut identities: Vec<_> = bindings.iter().map(|b| (&b.issuer, &b.subject)).collect();
    identities.sort_unstable();
    identities.dedup();
    for (issuer, subject) in identities {
        sqlx::query(
            "select user_id from external_identities where issuer=$1 and subject=$2 for share",
        )
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn valid_binding(conn: &mut PgConnection, binding: &Binding) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        "select exists(select 1 from users u \
         join personal_libraries p on p.user_id=u.id \
         join library l on l.id=p.library_id and l.kind=p.library_kind \
         join external_identities e on e.user_id=u.id \
         where u.id=$1 and u.disabled_at is null and p.library_id=$2 \
           and l.kind='personal' and e.issuer=$3 and e.subject=$4)",
    )
    .bind(binding.user)
    .bind(binding.library)
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .fetch_one(conn)
    .await
}

pub struct WebLogin<'a> {
    pub browser: &'a [u8; 32],
    pub challenge: &'a [u8; 32],
    pub previous: Option<&'a [u8; 32]>,
    pub issuer: &'a str,
    pub subject: &'a str,
    pub origin: &'a str,
    pub token: &'a [u8; 32],
    pub csrf: &'a [u8; 32],
    pub credential: &'a [u8; 32],
}

pub async fn complete_web_login(pool: &PgPool, login: WebLogin<'_>) -> sqlx::Result<Option<i64>> {
    let mut tx = pool.begin().await?;
    lock_browser(&mut tx, login.browser).await?;
    if sqlx::query(
        "select token_hash from web_challenges \
         where token_hash=$1 and browser_hash=$2 for update",
    )
    .bind(login.challenge.as_slice())
    .bind(login.browser.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .is_none()
    {
        denied(tx, WebSessionAction::Login).await?;
        return Ok(None);
    }
    let candidate = sqlx::query(
        "select e.user_id, p.library_id, e.issuer, e.subject \
         from external_identities e join personal_libraries p on p.user_id=e.user_id \
         where e.issuer=$1 and e.subject=$2",
    )
    .bind(login.issuer)
    .bind(login.subject)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(candidate) = candidate else {
        denied(tx, WebSessionAction::Login).await?;
        return Ok(None);
    };
    let target = Binding::from_row(&candidate);
    let old = sqlx::query(
        "select user_id,library_id,issuer,subject,token_hash,api_key_id \
         from web_sessions where browser_hash=$1 and revoked_at is null",
    )
    .bind(login.browser.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let mut bindings = vec![target];
    if let Some(old) = &old {
        bindings.push(Binding::from_row(old));
    }
    lock_bindings(&mut tx, &bindings).await?;
    if let Some(old) = &old {
        let key: i64 = old.get("api_key_id");
        sqlx::query("select id from api_keys where id=$1 for update")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?;
        sqlx::query("select token_hash from web_sessions where token_hash=$1 for update")
            .bind(old.get::<Vec<u8>, _>("token_hash"))
            .fetch_optional(&mut *tx)
            .await?;
    }
    // A challenge can refresh the browser cookie, never the session lifetime.
    // The browser may therefore retain its binding after dropping an expired
    // session cookie. Check expiry only after all acquired authority-row waits.
    match (&old, login.previous) {
        (Some(old), previous) => {
            let current = sqlx::query(
                "select s.expires_at<=clock_timestamp() as expired, \
                 s.revoked_at is null and s.origin=$2 and s.api_key_id=$3 \
                 and k.user_id=s.user_id and k.revoked_at is null as credential_live \
                 from web_sessions s join api_keys k on k.id=s.api_key_id \
                 where s.token_hash=$1",
            )
            .bind(old.get::<Vec<u8>, _>("token_hash"))
            .bind(login.origin)
            .bind(old.get::<i64, _>("api_key_id"))
            .fetch_one(&mut *tx)
            .await?;
            let expired: bool = current.get("expired");
            let matches = previous
                .is_some_and(|previous| old.get::<Vec<u8>, _>("token_hash") == previous.as_slice());
            if (!matches && !(expired && previous.is_none()))
                || (!expired
                    && (!current.get::<bool, _>("credential_live")
                        || !valid_binding(&mut tx, &bindings[1]).await?))
            {
                denied(tx, WebSessionAction::Login).await?;
                return Ok(None);
            }
        }
        (None, None) => {}
        (None, Some(_)) => {
            denied(tx, WebSessionAction::Login).await?;
            return Ok(None);
        }
    }
    let challenge_live: bool = sqlx::query_scalar(
        "select expires_at>clock_timestamp() and origin=$2 from web_challenges where token_hash=$1",
    )
    .bind(login.challenge.as_slice())
    .bind(login.origin)
    .fetch_one(&mut *tx)
    .await?;
    if !challenge_live || !valid_binding(&mut tx, &bindings[0]).await? {
        denied(tx, WebSessionAction::Login).await?;
        return Ok(None);
    }
    if let Some(old) = &old {
        revoke(&mut tx, old.get("api_key_id")).await?;
    }
    let key: i64 = sqlx::query_scalar(
        "insert into api_keys(user_id,name,token_hash) values($1,'Web session',$2) returning id",
    )
    .bind(bindings[0].user)
    .bind(login.credential.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "insert into api_key_user_permissions(api_key_id,library,notes,write,files) \
         values($1,true,true,true,true)",
    )
    .bind(key)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "insert into api_key_all_groups_permissions(api_key_id,library,write) values($1,true,true)",
    )
    .bind(key)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "insert into web_sessions(token_hash,browser_hash,csrf_hash,user_id,library_id,issuer,subject,api_key_id,origin) \
         values($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(login.token.as_slice())
    .bind(login.browser.as_slice())
    .bind(login.csrf.as_slice())
    .bind(bindings[0].user)
    .bind(bindings[0].library)
    .bind(login.issuer)
    .bind(login.subject)
    .bind(key)
    .bind(login.origin)
    .execute(&mut *tx)
    .await?;
    sqlx::query("delete from web_challenges where token_hash=$1")
        .bind(login.challenge.as_slice())
        .execute(&mut *tx)
        .await?;
    append_web(&mut tx, WebSessionAction::Login, Some(bindings[0].user)).await?;
    tx.commit().await?;
    Ok(Some(bindings[0].user))
}

async fn revoke(conn: &mut PgConnection, key: i64) -> sqlx::Result<()> {
    sqlx::query("update api_keys set revoked_at=clock_timestamp() where id=$1")
        .bind(key)
        .execute(&mut *conn)
        .await?;
    sqlx::query("update web_sessions set revoked_at=clock_timestamp() where api_key_id=$1")
        .bind(key)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn logout_web_session(
    pool: &PgPool,
    browser: &[u8; 32],
    token: &[u8; 32],
    csrf: &[u8; 32],
    origin: &str,
) -> sqlx::Result<bool> {
    let mut tx = pool.begin().await?;
    lock_browser(&mut tx, browser).await?;
    let session = sqlx::query(
        "select user_id,library_id,issuer,subject,api_key_id from web_sessions \
         where token_hash=$1 and browser_hash=$2",
    )
    .bind(token.as_slice())
    .bind(browser.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(session) = session else {
        denied(tx, WebSessionAction::Logout).await?;
        return Ok(false);
    };
    let binding = Binding::from_row(&session);
    lock_bindings(&mut tx, std::slice::from_ref(&binding)).await?;
    let key: i64 = session.get("api_key_id");
    sqlx::query("select id from api_keys where id=$1 for update")
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
    sqlx::query("select token_hash from web_sessions where token_hash=$1 for update")
        .bind(token.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
    let live: bool = sqlx::query_scalar(
        "select exists(select 1 from web_sessions s join api_keys k \
         on k.id=s.api_key_id and k.user_id=s.user_id \
         where s.token_hash=$1 and s.browser_hash=$2 and s.csrf_hash=$3 \
         and s.revoked_at is null and k.revoked_at is null \
         and s.expires_at>clock_timestamp() and k.id=$4 and s.origin=$5)",
    )
    .bind(token.as_slice())
    .bind(browser.as_slice())
    .bind(csrf.as_slice())
    .bind(key)
    .bind(origin)
    .fetch_one(&mut *tx)
    .await?;
    if !live || !valid_binding(&mut tx, &binding).await? {
        denied(tx, WebSessionAction::Logout).await?;
        return Ok(false);
    }
    revoke(&mut tx, key).await?;
    append_web(&mut tx, WebSessionAction::Logout, Some(binding.user)).await?;
    tx.commit().await?;
    Ok(true)
}

/// Only this constructor can produce a transaction carrying live instance
/// authority. Admission drops it before reading a body; mutation obtains a new
/// guard, keeping validation, mutation and audit in one transaction.
pub struct AdminGuard<'a> {
    pub(super) tx: sqlx::Transaction<'a, sqlx::Postgres>,
    pub(super) actor: i64,
    pub(super) audit: crate::domain::AdminAudit,
}

pub enum AdminDenial {
    Unauthenticated,
    Unauthorized,
}

pub async fn admin_guard<'a>(
    pool: &'a PgPool,
    proof: &crate::domain::WebSessionProof,
    audit: &mut crate::domain::AdminAudit,
) -> sqlx::Result<Result<AdminGuard<'a>, AdminDenial>> {
    let mut tx = pool.begin().await?;
    sqlx::query("select xotero_lock_instance_authority()")
        .execute(&mut *tx)
        .await?;
    let candidate = sqlx::query(
        "select user_id,library_id,issuer,subject,api_key_id \
         from web_sessions where token_hash=$1 and browser_hash=$2",
    )
    .bind(proof.token.as_slice())
    .bind(proof.browser.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(candidate) = candidate else {
        return Ok(Err(AdminDenial::Unauthenticated));
    };
    let binding = Binding::from_row(&candidate);
    let key: i64 = candidate.get("api_key_id");
    sqlx::query("select xotero_lock_admin_users($1,$2)")
        .bind(binding.user)
        .bind(audit.subject.map(crate::domain::UserId::get))
        .execute(&mut *tx)
        .await?;
    sqlx::query("select id from api_keys where id=$1 for share")
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
    sqlx::query("select token_hash from web_sessions where token_hash=$1 for share")
        .bind(proof.token.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
    // Fresh READ COMMITTED statement after every possible wait. Never follow a
    // changed discovery binding: that could request an earlier lock out of order.
    let live: bool = sqlx::query_scalar(
        "select exists(select 1 from web_sessions s join api_keys k \
         on k.id=s.api_key_id and k.user_id=s.user_id \
         where s.token_hash=$1 and s.browser_hash=$2 and s.origin=$3 \
         and s.user_id=$4 and s.library_id=$5 and s.issuer=$6 and s.subject=$7 \
         and s.api_key_id=$8 and s.revoked_at is null and k.revoked_at is null \
         and s.expires_at>clock_timestamp())",
    )
    .bind(proof.token.as_slice())
    .bind(proof.browser.as_slice())
    .bind(&proof.origin)
    .bind(binding.user)
    .bind(binding.library)
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    if !live || !valid_binding(&mut tx, &binding).await? {
        return Ok(Err(AdminDenial::Unauthenticated));
    }
    audit.actor = crate::domain::UserId::new(binding.user);
    if let Some(csrf) = proof.csrf {
        let matches: bool =
            sqlx::query_scalar("select csrf_hash=$2 from web_sessions where token_hash=$1")
                .bind(proof.token.as_slice())
                .bind(csrf.as_slice())
                .fetch_one(&mut *tx)
                .await?;
        if !matches {
            return Ok(Err(AdminDenial::Unauthorized));
        }
    }
    let role: bool =
        sqlx::query_scalar("select exists(select 1 from instance_admins where user_id=$1)")
            .bind(binding.user)
            .fetch_one(&mut *tx)
            .await?;
    if !role {
        return Ok(Err(AdminDenial::Unauthorized));
    }
    Ok(Ok(AdminGuard {
        tx,
        actor: binding.user,
        audit: audit.clone(),
    }))
}
