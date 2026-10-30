use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use super::audit::{append_admin, AuditOutcome};
use super::web_sessions::AdminGuard;
use crate::domain::{
    AdminAction, AdminAudit, CreateUser, ExternalIdentity, SetInstanceAdmin, UpdateUser, UserId,
};

pub enum AdminMutation {
    Create(CreateUser),
    Update(UpdateUser),
    Role(SetInstanceAdmin),
    Link(ExternalIdentity),
    Unlink(ExternalIdentity),
}

pub enum AdminResult {
    Created { user: i64, library: i64 },
    Changed,
    Missing,
    Conflict,
}

pub async fn admin_audit(pool: &PgPool) -> sqlx::Result<AdminAudit> {
    Ok(AdminAudit {
        request_id: sqlx::query_scalar("select gen_random_uuid()::text")
            .fetch_one(pool)
            .await?,
        actor: None,
        subject: None,
    })
}

pub async fn deny_admin(
    pool: &PgPool,
    action: AdminAction,
    audit: &AdminAudit,
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    append_admin(&mut tx, (audit, action, AuditOutcome::Denied)).await?;
    tx.commit().await
}

impl AdminGuard<'_> {
    pub async fn admit(self) -> sqlx::Result<()> {
        self.tx.commit().await
    }

    pub async fn list(mut self) -> sqlx::Result<Value> {
        let rows = sqlx::query(
            "select u.id,u.username,u.display_name,u.disabled_at is not null as disabled, \
             p.library_id,exists(select 1 from instance_admins a where a.user_id=u.id) as admin \
             from users u left join personal_libraries p on p.user_id=u.id order by u.id",
        )
        .fetch_all(&mut *self.tx)
        .await?;
        let users: Vec<_> = rows
            .iter()
            .map(|row| {
                json!({
                    "userID":row.get::<i64,_>("id"),
                    "libraryID":row.get::<Option<i64>,_>("library_id"),
                    "username":row.get::<String,_>("username"),
                    "displayName":row.get::<String,_>("display_name"),
                    "disabled":row.get::<bool,_>("disabled"),
                    "instanceAdmin":row.get::<bool,_>("admin"),
                })
            })
            .collect();
        self.audit(None, AdminAction::List, AuditOutcome::Success)
            .await?;
        self.tx.commit().await?;
        Ok(json!(users))
    }

    async fn audit(
        &mut self,
        target: Option<UserId>,
        action: AdminAction,
        outcome: AuditOutcome,
    ) -> sqlx::Result<()> {
        self.audit.subject = target;
        append_admin(&mut self.tx, (&self.audit, action, outcome)).await
    }

    pub async fn mutate(
        mut self,
        target: Option<UserId>,
        mutation: AdminMutation,
    ) -> sqlx::Result<AdminResult> {
        // The invariant core already records this exact action, including
        // missing/noop/conflict. Do not append a second unlink event.
        if let AdminMutation::Unlink(identity) = mutation {
            let target =
                target.ok_or_else(|| sqlx::Error::Protocol("admin target required".into()))?;
            let outcome = self
                .reduce(target, "unlink-identity", Some(&identity))
                .await?;
            if outcome == "success" {
                self.end_sessions(target, Some(&identity)).await?;
            }
            let result = match outcome.as_str() {
                "success" | "noop" => AdminResult::Changed,
                "missing" => AdminResult::Missing,
                "conflict" => AdminResult::Conflict,
                _ => return Err(sqlx::Error::Protocol("invalid authority outcome".into())),
            };
            self.tx.commit().await?;
            return Ok(result);
        }
        let action = match &mutation {
            AdminMutation::Create(_) => AdminAction::Create,
            AdminMutation::Update(_) => AdminAction::Update,
            AdminMutation::Role(_) => AdminAction::Role,
            AdminMutation::Link(_) => AdminAction::Link,
            AdminMutation::Unlink(_) => AdminAction::Unlink,
        };
        // A failed uniqueness check must roll back library allocation too, but
        // its safe denial event must survive. Unexpected SQL/audit errors abort
        // the whole transaction and are never logged with failing row contents.
        sqlx::query("savepoint admin_mutation")
            .execute(&mut *self.tx)
            .await?;
        let result = self.apply(target, mutation).await;
        let (result, outcome) = match result {
            Err(sqlx::Error::Database(ref error)) if error.is_unique_violation() => {
                sqlx::query("rollback to savepoint admin_mutation")
                    .execute(&mut *self.tx)
                    .await?;
                (AdminResult::Conflict, AuditOutcome::Denied)
            }
            Err(error) => return Err(error),
            Ok(result) => result,
        };
        let subject = match &result {
            AdminResult::Created { user, .. } => UserId::new(*user),
            AdminResult::Changed | AdminResult::Missing | AdminResult::Conflict => target,
        };
        self.audit(subject, action, outcome).await?;
        self.tx.commit().await?;
        Ok(result)
    }

    async fn apply(
        &mut self,
        target: Option<UserId>,
        mutation: AdminMutation,
    ) -> sqlx::Result<(AdminResult, AuditOutcome)> {
        if let AdminMutation::Create(input) = mutation {
            let library: i64 = sqlx::query_scalar(
                "insert into library(version,kind) values(0,'personal') returning id",
            )
            .fetch_one(&mut *self.tx)
            .await?;
            let user: i64 = sqlx::query_scalar(
                "insert into users(username,display_name) values($1,$2) returning id",
            )
            .bind(input.username)
            .bind(input.display_name)
            .fetch_one(&mut *self.tx)
            .await?;
            sqlx::query("insert into personal_libraries(user_id,library_id) values($1,$2)")
                .bind(user)
                .bind(library)
                .execute(&mut *self.tx)
                .await?;
            sqlx::query("insert into external_identities(issuer,subject,user_id) values($1,$2,$3)")
                .bind(input.issuer)
                .bind(input.subject)
                .bind(user)
                .execute(&mut *self.tx)
                .await?;
            return Ok((
                AdminResult::Created { user, library },
                AuditOutcome::Success,
            ));
        }
        let target = target.ok_or_else(|| sqlx::Error::Protocol("admin target required".into()))?;
        let row = sqlx::query(
            "select display_name,disabled_at is not null as disabled from users where id=$1",
        )
        .bind(target.get())
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some(row) = row else {
            return Ok((AdminResult::Missing, AuditOutcome::Denied));
        };
        let changed = match mutation {
            AdminMutation::Create(_) => {
                return Err(sqlx::Error::Protocol("unexpected create".into()))
            }
            AdminMutation::Update(input) => {
                if input.disabled == Some(true) {
                    let owns: bool = sqlx::query_scalar(
                        "select exists(select 1 from groups where owner_user_id=$1)",
                    )
                    .bind(target.get())
                    .fetch_one(&mut *self.tx)
                    .await?;
                    if owns {
                        return Ok((AdminResult::Conflict, AuditOutcome::Denied));
                    }
                    match self.reduce(target, "disable-user", None).await?.as_str() {
                        "conflict" => return Ok((AdminResult::Conflict, AuditOutcome::Denied)),
                        "success" => self.end_sessions(target, None).await?,
                        _ => {}
                    }
                }
                if input.disabled == Some(false) && !self.usable(target).await? {
                    return Ok((AdminResult::Conflict, AuditOutcome::Denied));
                }
                let changed = input
                    .display_name
                    .as_ref()
                    .is_some_and(|name| name != &row.get::<String, _>("display_name"))
                    || input
                        .disabled
                        .is_some_and(|disabled| disabled != row.get::<bool, _>("disabled"));
                sqlx::query(
                    "update users set display_name=coalesce($2,display_name), \
                     disabled_at=case when $3=false then null else disabled_at end where id=$1",
                )
                .bind(target.get())
                .bind(input.display_name)
                .bind(input.disabled)
                .execute(&mut *self.tx)
                .await?;
                changed
            }
            AdminMutation::Role(input) => {
                if input.enabled {
                    if row.get::<bool, _>("disabled") || !self.usable(target).await? {
                        return Ok((AdminResult::Conflict, AuditOutcome::Denied));
                    }
                    sqlx::query(
                        "insert into instance_admins(user_id) values($1) on conflict do nothing",
                    )
                    .bind(target.get())
                    .execute(&mut *self.tx)
                    .await?
                    .rows_affected()
                        != 0
                } else {
                    match self.reduce(target, "revoke-admin", None).await?.as_str() {
                        "conflict" => return Ok((AdminResult::Conflict, AuditOutcome::Denied)),
                        "success" => true,
                        "noop" => false,
                        _ => return Err(sqlx::Error::Protocol("invalid authority outcome".into())),
                    }
                }
            }
            AdminMutation::Link(identity) => {
                let mapped: Option<i64> = sqlx::query_scalar(
                    "select user_id from external_identities where issuer=$1 and subject=$2",
                )
                .bind(&identity.issuer)
                .bind(&identity.subject)
                .fetch_optional(&mut *self.tx)
                .await?;
                match mapped {
                    Some(user) if user != target.get() => {
                        return Ok((AdminResult::Conflict, AuditOutcome::Denied))
                    }
                    Some(_) => false,
                    None => {
                        sqlx::query("insert into external_identities(issuer,subject,user_id) values($1,$2,$3)")
                            .bind(identity.issuer).bind(identity.subject).bind(target.get())
                            .execute(&mut *self.tx).await?;
                        true
                    }
                }
            }
            AdminMutation::Unlink(_) => {
                return Err(sqlx::Error::Protocol("unexpected unlink".into()))
            }
        };
        Ok((
            AdminResult::Changed,
            if changed {
                AuditOutcome::Success
            } else {
                AuditOutcome::Noop
            },
        ))
    }

    async fn usable(&mut self, target: UserId) -> sqlx::Result<bool> {
        sqlx::query_scalar(
            "select exists(select 1 from personal_libraries p join library l \
             on l.id=p.library_id and l.kind=p.library_kind where p.user_id=$1 \
             and l.kind='personal' and exists(select 1 from external_identities e where e.user_id=$1))",
        ).bind(target.get()).fetch_one(&mut *self.tx).await
    }

    // Session validity follows live identity state, so without an explicit
    // revocation a later re-enable or relink would revive these sessions.
    // Keys lock before sessions, matching logout.
    async fn end_sessions(
        &mut self,
        target: UserId,
        identity: Option<&ExternalIdentity>,
    ) -> sqlx::Result<()> {
        const BOUND: &str = "user_id=$1 and revoked_at is null \
             and ($2::text is null or (issuer=$2 and subject=$3))";
        sqlx::query(&format!(
            "update api_keys set revoked_at=clock_timestamp() where revoked_at is null \
             and id in (select api_key_id from web_sessions where {BOUND})"
        ))
        .bind(target.get())
        .bind(identity.map(|i| i.issuer.as_str()))
        .bind(identity.map(|i| i.subject.as_str()))
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(&format!(
            "update web_sessions set revoked_at=clock_timestamp() where {BOUND}"
        ))
        .bind(target.get())
        .bind(identity.map(|i| i.issuer.as_str()))
        .bind(identity.map(|i| i.subject.as_str()))
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    async fn reduce(
        &mut self,
        target: UserId,
        change: &str,
        identity: Option<&ExternalIdentity>,
    ) -> sqlx::Result<String> {
        sqlx::query_scalar(
            "select xotero_change_authority($1,$2::authority_change,$3,$4,$5,$6::uuid)::text",
        )
        .bind(target.get())
        .bind(change)
        .bind(identity.map(|i| i.issuer.as_str()))
        .bind(identity.map(|i| i.subject.as_str()))
        .bind(self.actor)
        .bind(&self.audit.request_id)
        .fetch_one(&mut *self.tx)
        .await
    }
}
