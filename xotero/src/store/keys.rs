use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use super::audit::{append_key, AuditOutcome};
use super::web_sessions::{admin_guard_with_key, AdminDenial, SessionCandidate};
use crate::domain::{
    AdminAudit, ApiKeyId, CreateKey, KeyAction, KeyProof, Permissions, UserId, WebSessionProof,
};

pub async fn deny_key(
    pool: &PgPool,
    audit: &AdminAudit,
    action: KeyAction,
    key: Option<ApiKeyId>,
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    append_key(&mut tx, audit, action, key, AuditOutcome::Denied).await?;
    tx.commit().await
}

/// Only constructors below can supply live authority and its transaction.
pub struct KeyGuard<'a> {
    tx: sqlx::Transaction<'a, sqlx::Postgres>,
    audit: AdminAudit,
    user: i64,
    target: Option<ApiKeyId>,
    target_locked: bool,
    creation: Option<CreateKey>,
}

pub async fn admin_key_guard<'a>(
    pool: &'a PgPool,
    proof: &WebSessionProof,
    audit: &mut AdminAudit,
    target: ApiKeyTarget,
) -> sqlx::Result<Result<KeyGuard<'a>, AdminDenial>> {
    let key = match target {
        ApiKeyTarget::Named(key) => Some(key),
        ApiKeyTarget::None => None,
        ApiKeyTarget::Current => return Ok(Err(AdminDenial::Unauthorized)),
    };
    let guard = match admin_guard_with_key(pool, proof, audit, key).await? {
        Ok(guard) => guard,
        Err(denial) => return Ok(Err(denial)),
    };
    let user = audit
        .subject
        .ok_or_else(|| sqlx::Error::Protocol("key subject required".into()))?;
    Ok(Ok(KeyGuard {
        tx: guard.tx,
        audit: guard.audit,
        user: user.get(),
        target: key,
        target_locked: guard.target_key_locked,
        creation: None,
    }))
}

#[derive(Clone, Copy)]
pub enum ApiKeyTarget {
    None,
    Named(ApiKeyId),
    Current,
}

pub async fn key_guard<'a>(
    pool: &'a PgPool,
    proof: &KeyProof,
    audit: &mut AdminAudit,
    target: ApiKeyTarget,
    creation: Option<CreateKey>,
) -> sqlx::Result<Result<KeyGuard<'a>, AdminDenial>> {
    let mut tx = pool.begin().await?;
    let (session, key, user, library) = match proof {
        KeyProof::Session(proof) => {
            let Some(candidate) = SessionCandidate::discover(&mut tx, proof).await? else {
                return Ok(Err(AdminDenial::Unauthenticated));
            };
            let binding = (candidate.key, candidate.user(), candidate.library());
            (Some(candidate), binding.0, binding.1, binding.2)
        }
        KeyProof::Database(hash) => {
            let Some((key, principal, _)) = super::authenticate_api_key(&mut *tx, hash).await?
            else {
                return Ok(Err(AdminDenial::Unauthenticated));
            };
            (
                None,
                key.get(),
                principal.user_id.get(),
                principal.library_id.get(),
            )
        }
    };
    let target = match target {
        ApiKeyTarget::None => None,
        ApiKeyTarget::Named(key) => Some(key),
        ApiKeyTarget::Current => ApiKeyId::new(key),
    };
    // Requested scopes determine a complete lock plan before taking any row
    // locks. A changed group binding is denied, never chased after a wait.
    let requested: Vec<i64> = creation
        .as_ref()
        .map(|input| {
            input
                .access
                .groups
                .individual
                .iter()
                .map(|g| g.group_id)
                .collect()
        })
        .unwrap_or_default();
    let groups =
        sqlx::query("select id,library_id,owner_user_id from groups where id=any($1) order by id")
            .bind(&requested)
            .fetch_all(&mut *tx)
            .await?;
    let mut libraries = vec![library];
    libraries.extend(groups.iter().map(|row| row.get::<i64, _>("library_id")));
    libraries.sort_unstable();
    libraries.dedup();
    sqlx::query("select id from library where id=any($1) order by id for share")
        .bind(&libraries)
        .fetch_all(&mut *tx)
        .await?;
    let locked_groups = sqlx::query(
        "select id,library_id,owner_user_id from groups where id=any($1) order by id for share",
    )
    .bind(&requested)
    .fetch_all(&mut *tx)
    .await?;
    if groups.len() != locked_groups.len()
        || groups.iter().zip(&locked_groups).any(|(before, after)| {
            ["id", "library_id", "owner_user_id"]
                .iter()
                .any(|column| before.get::<i64, _>(*column) != after.get::<i64, _>(*column))
        })
    {
        return Ok(Err(AdminDenial::Unauthorized));
    }
    let mut users = vec![user];
    users.extend(groups.iter().map(|row| row.get::<i64, _>("owner_user_id")));
    users.sort_unstable();
    users.dedup();
    sqlx::query("select id from users where id=any($1) order by id for share")
        .bind(&users)
        .fetch_all(&mut *tx)
        .await?;
    let ownership = sqlx::query(
        "select user_id from personal_libraries \
         where user_id=$1 and library_id=$2 for share",
    )
    .bind(user)
    .bind(library)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !ownership {
        return Ok(Err(AdminDenial::Unauthenticated));
    }
    if let Some(session) = &session {
        if !session.lock_identity(&mut tx).await? {
            return Ok(Err(AdminDenial::Unauthenticated));
        }
    }
    let mut keys = vec![key];
    keys.extend(target.map(ApiKeyId::get));
    keys.sort_unstable();
    keys.dedup();
    let mut target_locked = false;
    for id in keys {
        let query = if target.is_some_and(|target| target.get() == id) {
            "select id from api_keys where id=$1 for update"
        } else {
            "select id from api_keys where id=$1 for share"
        };
        let locked = sqlx::query(query)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if target.is_some_and(|target| target.get() == id) {
            target_locked = locked;
        }
    }
    let personal = sqlx::query(
        "select library,notes,write,files from api_key_user_permissions \
         where api_key_id=$1 for share",
    )
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?;
    let memberships: Vec<i64> = sqlx::query_scalar(
        "select group_id from group_memberships \
         where user_id=$1 and group_id=any($2) order by group_id for share",
    )
    .bind(user)
    .bind(&requested)
    .fetch_all(&mut *tx)
    .await?;
    let all = sqlx::query(
        "select library,write from api_key_all_groups_permissions where api_key_id=$1 for share",
    )
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?;
    let explicit: Vec<i64> = sqlx::query_scalar(
        "select group_id from api_key_group_permissions \
         where api_key_id=$1 and group_id=any($2) order by group_id for share",
    )
    .bind(key)
    .bind(&requested)
    .fetch_all(&mut *tx)
    .await?;
    // Session validation may itself wait, so all permission reads below are
    // fresh and only positively locked optional grants can contribute.
    match (proof, &session) {
        (KeyProof::Session(proof), Some(session)) => {
            if let Err(denial) = session.validate(&mut tx, proof, audit).await? {
                return Ok(Err(denial));
            }
        }
        (KeyProof::Database(hash), None) => {
            let current = super::authenticate_api_key(&mut *tx, hash).await?;
            if !current.is_some_and(|(id, principal, _)| {
                id.get() == key
                    && principal.user_id.get() == user
                    && principal.library_id.get() == library
            }) || personal.is_none()
            {
                return Ok(Err(AdminDenial::Unauthenticated));
            }
            let internal: bool =
                sqlx::query_scalar("select exists(select 1 from web_sessions where api_key_id=$1)")
                    .bind(key)
                    .fetch_one(&mut *tx)
                    .await?;
            if internal {
                return Ok(Err(AdminDenial::Unauthorized));
            }
            audit.actor = UserId::new(user);
        }
        _ => return Err(sqlx::Error::Protocol("invalid session candidate".into())),
    }
    audit.subject = UserId::new(user);
    if let Some(input) = &creation {
        if session.is_none() {
            let current = sqlx::query(
                "select library,notes,write,files from api_key_user_permissions where api_key_id=$1",
            )
            .bind(key)
            .fetch_one(&mut *tx)
            .await?;
            let wanted = input.access.user;
            if [
                ("library", wanted.library),
                ("notes", wanted.notes),
                ("write", wanted.write),
                ("files", wanted.files),
            ]
            .iter()
            .any(|(bit, wanted)| *wanted && !current.get::<bool, _>(*bit))
            {
                return Ok(Err(AdminDenial::Unauthorized));
            }
            let wanted = input.access.groups.all;
            if (wanted.library && !all.as_ref().is_some_and(|row| row.get("library")))
                || (wanted.write && !all.as_ref().is_some_and(|row| row.get("write")))
            {
                return Ok(Err(AdminDenial::Unauthorized));
            }
        }
        for group in &input.access.groups.individual {
            if !memberships.contains(&group.group_id) {
                return Ok(Err(AdminDenial::Unauthorized));
            }
            let group_id = crate::domain::GroupId::new(group.group_id)
                .ok_or_else(|| sqlx::Error::Protocol("invalid group scope".into()))?;
            let user_id = UserId::new(user)
                .ok_or_else(|| sqlx::Error::Protocol("invalid key owner".into()))?;
            let access = super::groups::resolve_group_library_with_grants(
                &mut *tx,
                group_id,
                user_id,
                ApiKeyId::new(key).filter(|_| session.is_none()),
                session.as_ref().map(|_| Permissions::recovery(true)),
                (all.is_some(), explicit.contains(&group.group_id)),
            )
            .await?;
            let super::GroupLibraryResolution::Allowed(access) = access else {
                return Ok(Err(AdminDenial::Unauthorized));
            };
            if group.write && !access.permissions.write {
                return Ok(Err(AdminDenial::Unauthorized));
            }
            // Explicit write bypasses group editing policy in the data API.
            // Converting a policy-limited wildcard would escape future policy
            // tightening even if the issuer can write at this instant.
            if session.is_none() && group.write {
                let inherited: bool = sqlx::query_scalar(
                    "select exists(select 1 from api_key_group_permissions \
                     where api_key_id=$1 and group_id=$2 and library and write)",
                )
                .bind(key)
                .bind(group.group_id)
                .fetch_one(&mut *tx)
                .await?;
                if !explicit.contains(&group.group_id) || !inherited {
                    return Ok(Err(AdminDenial::Unauthorized));
                }
            }
        }
    }
    Ok(Ok(KeyGuard {
        tx,
        audit: audit.clone(),
        user,
        target,
        target_locked,
        creation,
    }))
}

impl KeyGuard<'_> {
    pub async fn admit(self) -> sqlx::Result<()> {
        self.tx.commit().await
    }

    async fn metadata(&mut self, key: Option<ApiKeyId>) -> sqlx::Result<Vec<Value>> {
        let rows = sqlx::query(
            "select k.id,k.name,k.created_at::text,k.revoked_at::text, \
             p.library,p.notes,p.write,p.files, \
             coalesce(a.library,false) as all_library,coalesce(a.write,false) as all_write \
             from api_keys k join api_key_user_permissions p on p.api_key_id=k.id \
             left join api_key_all_groups_permissions a on a.api_key_id=k.id \
             where k.user_id=$1 and ($2::bigint is null or k.id=$2) \
             and not exists(select 1 from web_sessions s where s.api_key_id=k.id) order by k.id",
        )
        .bind(self.user)
        .bind(key.map(ApiKeyId::get))
        .fetch_all(&mut *self.tx)
        .await?;
        let mut metadata = Vec::with_capacity(rows.len());
        for row in rows {
            let id: i64 = row.get("id");
            let groups = sqlx::query(
                "select group_id,library,write from api_key_group_permissions \
                 where api_key_id=$1 order by group_id",
            )
            .bind(id)
            .fetch_all(&mut *self.tx)
            .await?;
            let groups: Vec<Value> = groups
                .iter()
                .map(|g| {
                    json!({
                        "groupID":g.get::<i64,_>("group_id"),
                        "library":g.get::<bool,_>("library"),"write":g.get::<bool,_>("write")
                    })
                })
                .collect();
            metadata.push(json!({
                "id":id,"name":row.get::<String,_>("name"),
                "createdAt":row.get::<String,_>("created_at"),
                "revokedAt":row.get::<Option<String>,_>("revoked_at"),
                "access":{"user":{
                    "library":row.get::<bool,_>("library"),"notes":row.get::<bool,_>("notes"),
                    "write":row.get::<bool,_>("write"),"files":row.get::<bool,_>("files")
                },"groups":{"all":{
                    "library":row.get::<bool,_>("all_library"),"write":row.get::<bool,_>("all_write")
                },"individual":groups}}
            }));
        }
        Ok(metadata)
    }

    pub async fn list(mut self) -> sqlx::Result<Option<Value>> {
        let exists: bool = sqlx::query_scalar("select exists(select 1 from users where id=$1)")
            .bind(self.user)
            .fetch_one(&mut *self.tx)
            .await?;
        let metadata = if exists {
            Some(json!(self.metadata(None).await?))
        } else {
            None
        };
        let outcome = if exists {
            AuditOutcome::Success
        } else {
            AuditOutcome::Denied
        };
        append_key(&mut self.tx, &self.audit, KeyAction::List, None, outcome).await?;
        self.tx.commit().await?;
        Ok(metadata)
    }

    pub async fn issue(mut self, hash: &[u8; 32]) -> sqlx::Result<Value> {
        let input = self
            .creation
            .take()
            .ok_or_else(|| sqlx::Error::Protocol("validated creation required".into()))?;
        let id: i64 = sqlx::query_scalar(
            "insert into api_keys(user_id,name,token_hash) values($1,$2,$3) returning id",
        )
        .bind(self.user)
        .bind(input.name)
        .bind(hash.as_slice())
        .fetch_one(&mut *self.tx)
        .await?;
        let permissions = input.access.user;
        sqlx::query(
            "insert into api_key_user_permissions(api_key_id,library,notes,write,files) \
             values($1,$2,$3,$4,$5)",
        )
        .bind(id)
        .bind(permissions.library)
        .bind(permissions.notes)
        .bind(permissions.write)
        .bind(permissions.files)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "insert into api_key_all_groups_permissions(api_key_id,library,write) values($1,$2,$3)",
        )
        .bind(id)
        .bind(input.access.groups.all.library)
        .bind(input.access.groups.all.write)
        .execute(&mut *self.tx)
        .await?;
        for group in input.access.groups.individual {
            sqlx::query(
                "insert into api_key_group_permissions \
                 (api_key_id,user_id,group_id,library,write,policy_limited) \
                 values($1,$2,$3,$4,$5,true)",
            )
            .bind(id)
            .bind(self.user)
            .bind(group.group_id)
            .bind(group.library)
            .bind(group.write)
            .execute(&mut *self.tx)
            .await?;
        }
        let key = ApiKeyId::new(id)
            .ok_or_else(|| sqlx::Error::Protocol("invalid generated key".into()))?;
        let result = self
            .metadata(Some(key))
            .await?
            .pop()
            .ok_or_else(|| sqlx::Error::Protocol("issued key missing".into()))?;
        append_key(
            &mut self.tx,
            &self.audit,
            KeyAction::Create,
            Some(key),
            AuditOutcome::Success,
        )
        .await?;
        self.tx.commit().await?;
        Ok(result)
    }

    pub async fn revoke(mut self) -> sqlx::Result<bool> {
        let key = self
            .target
            .ok_or_else(|| sqlx::Error::Protocol("key target required".into()))?;
        let revoked: Option<bool> = sqlx::query_scalar(
            "select revoked_at is not null from api_keys k where id=$1 and user_id=$2 and $3 \
             and not exists(select 1 from web_sessions s where s.api_key_id=k.id)",
        )
        .bind(key.get())
        .bind(self.user)
        .bind(self.target_locked)
        .fetch_optional(&mut *self.tx)
        .await?;
        let outcome = match revoked {
            Some(false) => {
                sqlx::query("update api_keys set revoked_at=clock_timestamp() where id=$1")
                    .bind(key.get())
                    .execute(&mut *self.tx)
                    .await?;
                AuditOutcome::Success
            }
            Some(true) => AuditOutcome::Noop,
            None => AuditOutcome::Denied,
        };
        append_key(
            &mut self.tx,
            &self.audit,
            KeyAction::Revoke,
            Some(key),
            outcome,
        )
        .await?;
        self.tx.commit().await?;
        Ok(revoked.is_some())
    }
}
