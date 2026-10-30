use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use super::audit::{append_group, AuditOutcome};
use super::web_sessions::{AdminDenial, SessionCandidate};
use crate::domain::{
    AdminAudit, GroupAction, GroupChanges, GroupId, GroupTarget, LibraryId, UserId, WebSessionProof,
};

pub enum GroupDenial {
    Unauthenticated,
    Unauthorized,
    Missing,
    Conflict,
    Stale,
}

impl From<AdminDenial> for GroupDenial {
    fn from(value: AdminDenial) -> Self {
        match value {
            AdminDenial::Unauthenticated => Self::Unauthenticated,
            AdminDenial::Unauthorized => Self::Unauthorized,
        }
    }
}

struct Binding {
    id: i64,
    library: i64,
    owner: i64,
    membership: bool,
}

/// A live transaction, not an actor-ID capability. Its complete lock plan is
/// fixed before taking positive authority rows, including list membership.
pub struct GroupGuard<'a> {
    tx: sqlx::Transaction<'a, sqlx::Postgres>,
    audit: AdminAudit,
    target: GroupTarget,
    session: SessionCandidate,
    groups: Vec<Binding>,
    role_locked: bool,
}

pub async fn deny_group(
    pool: &PgPool,
    audit: &AdminAudit,
    target: GroupTarget,
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    append_group(&mut tx, audit, target, AuditOutcome::Denied).await?;
    tx.commit().await
}

pub async fn group_guard<'a>(
    pool: &'a PgPool,
    proof: &WebSessionProof,
    audit: &mut AdminAudit,
    mut target: GroupTarget,
) -> sqlx::Result<Result<GroupGuard<'a>, GroupDenial>> {
    let mut tx = pool.begin().await?;
    let Some(session) = SessionCandidate::discover(&mut tx, proof).await? else {
        append_group(&mut tx, audit, target, AuditOutcome::Denied).await?;
        tx.commit().await?;
        return Ok(Err(GroupDenial::Unauthenticated));
    };
    if matches!(target.action, GroupAction::Create) && !target.admin {
        target.owner = UserId::new(session.user());
    }
    let rows = sqlx::query(
        "select id,library_id,owner_user_id from groups g where \
         ($1::bigint is not null and id=$1) or \
         ($2 and ($3 or exists(select 1 from group_memberships m \
                              where m.group_id=g.id and m.user_id=$4))) order by id",
    )
    .bind(target.id.map(GroupId::get))
    .bind(matches!(target.action, GroupAction::List))
    .bind(target.admin)
    .bind(session.user())
    .fetch_all(&mut *tx)
    .await?;
    let groups: Vec<_> = rows
        .iter()
        .map(|row| Binding {
            id: row.get("id"),
            library: row.get("library_id"),
            owner: row.get("owner_user_id"),
            membership: false,
        })
        .collect();
    let mut libraries = vec![session.library()];
    libraries.extend(groups.iter().map(|g| g.library));
    libraries.sort_unstable();
    libraries.dedup();
    let mut complete = true;
    for library in libraries {
        let query = if target.action.mutation() && groups.iter().any(|g| g.library == library) {
            "select id from library where id=$1 for update"
        } else {
            "select id from library where id=$1 for share"
        };
        complete &= sqlx::query(query)
            .bind(library)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
    }
    for group in &groups {
        let query = if target.action.mutation() {
            "select library_id,owner_user_id from groups where id=$1 for update"
        } else {
            "select library_id,owner_user_id from groups where id=$1 for share"
        };
        let locked = sqlx::query(query)
            .bind(group.id)
            .fetch_optional(&mut *tx)
            .await?;
        complete &= locked.is_some_and(|row| {
            row.get::<i64, _>("library_id") == group.library
                && row.get::<i64, _>("owner_user_id") == group.owner
        });
    }
    let mut users = vec![session.user()];
    users.extend(groups.iter().map(|g| g.owner));
    users.extend(target.owner.map(UserId::get));
    users.extend(target.member.map(UserId::get));
    users.sort_unstable();
    users.dedup();
    // Missing requested owners are handled as404 after authenticating. Missing
    // actor/group owners cannot contribute positive evidence.
    let locked_users: Vec<i64> =
        sqlx::query_scalar("select id from users where id=any($1) order by id for share")
            .bind(&users)
            .fetch_all(&mut *tx)
            .await?;
    complete &= locked_users.contains(&session.user())
        && groups.iter().all(|g| locked_users.contains(&g.owner));
    let role_locked = if target.admin {
        sqlx::query("select user_id from instance_admins where user_id=$1 for share")
            .bind(session.user())
            .fetch_optional(&mut *tx)
            .await?
            .is_some()
    } else {
        false
    };
    let mapping = sqlx::query(
        "select user_id from personal_libraries where user_id=$1 and library_id=$2 for share",
    )
    .bind(session.user())
    .bind(session.library())
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    let identity = session.lock_identity(&mut tx).await?;
    let key = sqlx::query("select id from api_keys where id=$1 for share")
        .bind(session.key)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
    let mut guard = GroupGuard {
        tx,
        audit: audit.clone(),
        target,
        session,
        groups,
        role_locked,
    };
    for group in &mut guard.groups {
        let query = if matches!(
            target.action,
            GroupAction::Delete
                | GroupAction::SetMember
                | GroupAction::RemoveMember
                | GroupAction::TransferOwner
        ) {
            "select user_id from group_memberships where group_id=$1 order by user_id for update"
        } else {
            "select user_id from group_memberships where group_id=$1 order by user_id for share"
        };
        let members: Vec<i64> = sqlx::query_scalar(query)
            .bind(group.id)
            .fetch_all(&mut *guard.tx)
            .await?;
        group.membership = members.contains(&guard.session.user());
        complete &= members.contains(&group.owner);
    }
    if matches!(
        target.action,
        GroupAction::Delete | GroupAction::RemoveMember
    ) {
        sqlx::query(
            "select api_key_id from api_key_group_permissions \
             where group_id=$1 and ($2::bigint is null or user_id=$2) \
             order by api_key_id for update",
        )
        .bind(target.id.map(GroupId::get))
        .bind(target.member.map(UserId::get))
        .fetch_all(&mut *guard.tx)
        .await?;
    }
    let session_result = guard
        .session
        .validate(&mut guard.tx, proof, &mut guard.audit)
        .await?;
    audit.actor = guard.audit.actor;
    let result = if !mapping || !identity || !key {
        Err(GroupDenial::Unauthenticated)
    } else if let Err(denial) = session_result {
        Err(denial.into())
    } else if !complete {
        Err(GroupDenial::Conflict)
    } else if target
        .owner
        .or(target.member)
        .is_some_and(|owner| !locked_users.contains(&owner.get()))
    {
        Err(GroupDenial::Missing)
    } else {
        guard.authorized().await?
    };
    if let Err(denial) = result {
        guard.finish(AuditOutcome::Denied).await?;
        return Ok(Err(denial));
    }
    Ok(Ok(guard))
}

impl GroupGuard<'_> {
    async fn authorized(&mut self) -> sqlx::Result<Result<(), GroupDenial>> {
        if self.target.admin && !self.role_locked {
            return Ok(Err(GroupDenial::Unauthorized));
        }
        if self.target.id.is_some() && self.groups.is_empty() {
            return Ok(Err(GroupDenial::Missing));
        }
        if let Some(owner) = self.target.owner.or(self
            .target
            .member
            .filter(|_| matches!(self.target.action, GroupAction::SetMember)))
        {
            let enabled: Option<bool> =
                sqlx::query_scalar("select disabled_at is null from users where id=$1")
                    .bind(owner.get())
                    .fetch_optional(&mut *self.tx)
                    .await?;
            match enabled {
                None => return Ok(Err(GroupDenial::Missing)),
                Some(false) => return Ok(Err(GroupDenial::Conflict)),
                Some(true) => {}
            }
        }
        for group in &self.groups {
            let current = sqlx::query(
                "select g.version,g.library_id,g.owner_user_id,u.disabled_at is null as enabled, \
                 (select role from group_memberships where group_id=g.id and user_id=$2) as role \
                 from groups g join users u on u.id=g.owner_user_id where g.id=$1",
            )
            .bind(group.id)
            .bind(self.session.user())
            .fetch_optional(&mut *self.tx)
            .await?;
            let Some(current) = current else {
                return Ok(Err(GroupDenial::Missing));
            };
            if current.get::<i64, _>("library_id") != group.library
                || current.get::<i64, _>("owner_user_id") != group.owner
                || !current.get::<bool, _>("enabled")
            {
                return Ok(Err(GroupDenial::Conflict));
            }
            if !self.target.admin {
                let role: Option<String> = current.get("role");
                let allowed = group.membership
                    && match self.target.action {
                        GroupAction::List | GroupAction::Read => role.is_some(),
                        GroupAction::Update => {
                            matches!(role.as_deref(), Some("owner" | "admin"))
                        }
                        GroupAction::Delete
                        | GroupAction::SetMember
                        | GroupAction::RemoveMember
                        | GroupAction::TransferOwner => role.as_deref() == Some("owner"),
                        GroupAction::Create => false,
                    };
                if !allowed {
                    return Ok(Err(GroupDenial::Unauthorized));
                }
            }
            if self
                .target
                .expected
                .is_some_and(|expected| expected != current.get::<i64, _>("version"))
            {
                return Ok(Err(GroupDenial::Stale));
            }
            if self
                .target
                .member
                .is_some_and(|member| member.get() == group.owner)
            {
                return Ok(Err(GroupDenial::Conflict));
            }
            if matches!(self.target.action, GroupAction::TransferOwner) {
                if let Some(owner) = self.target.owner {
                    let member: bool = sqlx::query_scalar(
                        "select exists(select 1 from group_memberships where group_id=$1 and user_id=$2)",
                    )
                    .bind(group.id)
                    .bind(owner.get())
                    .fetch_one(&mut *self.tx)
                    .await?;
                    if !member {
                        return Ok(Err(GroupDenial::Conflict));
                    }
                }
            }
        }
        Ok(Ok(()))
    }

    async fn finish(mut self, outcome: AuditOutcome) -> sqlx::Result<()> {
        append_group(&mut self.tx, &self.audit, self.target, outcome).await?;
        self.tx.commit().await
    }

    pub async fn admit(self) -> sqlx::Result<()> {
        self.tx.commit().await
    }

    pub async fn read(mut self) -> sqlx::Result<Vec<Value>> {
        let ids: Vec<_> = self.groups.iter().map(|g| g.id).collect();
        let rows = sqlx::query_scalar(
            "select jsonb_build_object('groupID',id,'libraryID',library_id, \
             'ownerUserID',owner_user_id,'version',version,'name',name, \
             'description',description,'url',url,'type',type, \
             'libraryReading',library_reading,'libraryEditing',library_editing, \
             'fileEditing',file_editing) from groups where id=any($1) order by id",
        )
        .bind(ids)
        .fetch_all(&mut *self.tx)
        .await?;
        self.finish(AuditOutcome::Success).await?;
        Ok(rows)
    }

    pub async fn mutate(
        mut self,
        proof: &WebSessionProof,
        changes: GroupChanges,
    ) -> sqlx::Result<Result<Option<Value>, GroupDenial>> {
        let mut file_keys = Vec::<String>::new();
        if matches!(self.target.action, GroupAction::Delete) {
            let group = &self.groups[0];
            sqlx::query(
                "select kind,key from object where library_id=$1 order by kind,key for update",
            )
            .bind(group.library)
            .fetch_all(&mut *self.tx)
            .await?;
            file_keys = sqlx::query_scalar(
                "select item_key from file where library_id=$1 order by item_key",
            )
            .bind(group.library)
            .fetch_all(&mut *self.tx)
            .await?;
            let refs: Vec<_> = file_keys.iter().map(String::as_str).collect();
            super::files::lock_file_references(
                &mut self.tx,
                LibraryId::new(group.library)
                    .ok_or_else(|| sqlx::Error::Protocol("invalid group library".into()))?,
                &refs,
            )
            .await?;
        }
        // Expiry is time-sensitive even when all durable rows are locked.
        // This method requests no earlier lock after the object/blob set.
        if let Err(denial) = self
            .session
            .validate_locked(&mut self.tx, proof, &mut self.audit)
            .await?
        {
            self.finish(AuditOutcome::Denied).await?;
            return Ok(Err(denial.into()));
        }
        if let Err(denial) = self.authorized().await? {
            self.finish(AuditOutcome::Denied).await?;
            return Ok(Err(denial));
        }
        sqlx::query("savepoint group_mutation")
            .execute(&mut *self.tx)
            .await?;
        let (result, outcome) = match self.apply(changes, &file_keys).await {
            Ok(result) => result,
            Err(sqlx::Error::Database(error))
                if matches!(
                    error.code().as_deref(),
                    Some("23503" | "23505" | "23514" | "22003")
                ) =>
            {
                sqlx::query("rollback to savepoint group_mutation")
                    .execute(&mut *self.tx)
                    .await?;
                self.finish(AuditOutcome::Denied).await?;
                return Ok(Err(GroupDenial::Conflict));
            }
            Err(error) => return Err(error),
        };
        // Allocation may wait on an explicit-ID uniqueness contender. New rows
        // remain private until this final clock-sensitive proof and audit commit.
        if matches!(
            self.target.action,
            GroupAction::Create
                | GroupAction::SetMember
                | GroupAction::RemoveMember
                | GroupAction::TransferOwner
        ) {
            if let Err(denial) = self
                .session
                .validate_locked(&mut self.tx, proof, &mut self.audit)
                .await?
            {
                sqlx::query("rollback to savepoint group_mutation")
                    .execute(&mut *self.tx)
                    .await?;
                if matches!(self.target.action, GroupAction::Create) {
                    self.target.id = None;
                }
                self.finish(AuditOutcome::Denied).await?;
                return Ok(Err(denial.into()));
            }
        }
        self.finish(outcome).await?;
        Ok(Ok(result))
    }

    async fn apply(
        &mut self,
        changes: GroupChanges,
        file_keys: &[String],
    ) -> sqlx::Result<(Option<Value>, AuditOutcome)> {
        Ok(match self.target.action {
            GroupAction::Create => {
                let owner = self
                    .target
                    .owner
                    .ok_or_else(|| sqlx::Error::Protocol("group creation owner required".into()))?;
                // New rows have no pre-existing lock position. Skip explicit
                // configured IDs without locking or modifying an existing row.
                let library: i64 = loop {
                    if let Some(id) = sqlx::query_scalar(
                        "insert into library(version,kind) values(0,'group') \
                         on conflict(id) do nothing returning id",
                    )
                    .fetch_optional(&mut *self.tx)
                    .await?
                    {
                        break id;
                    }
                };
                let group: i64 = loop {
                    if let Some(id) = sqlx::query_scalar(
                        "insert into groups(library_id,owner_user_id,name,description,url, \
                         library_editing,file_editing) values($1,$2,$3,coalesce($4,''), \
                         coalesce($5,''),coalesce($6,'members'),coalesce($7,'members')) \
                         on conflict(id) do nothing returning id",
                    )
                    .bind(library)
                    .bind(owner.get())
                    .bind(&changes.name)
                    .bind(&changes.description)
                    .bind(&changes.url)
                    .bind(&changes.library_editing)
                    .bind(&changes.file_editing)
                    .fetch_optional(&mut *self.tx)
                    .await?
                    {
                        break id;
                    }
                };
                sqlx::query(
                    "insert into group_memberships(group_id,user_id,role) values($1,$2,'owner')",
                )
                .bind(group)
                .bind(owner.get())
                .execute(&mut *self.tx)
                .await?;
                self.target.id = GroupId::new(group);
                (
                    Some(json!({"groupID":group,"libraryID":library})),
                    AuditOutcome::Success,
                )
            }
            GroupAction::Update => {
                let changed = sqlx::query(
                    "update groups set name=coalesce($2,name),description=coalesce($3,description), \
                     url=coalesce($4,url),library_editing=coalesce($5,library_editing), \
                     file_editing=coalesce($6,file_editing),version=version+1, \
                     updated_at=clock_timestamp() where id=$1 and \
                     (name,description,url,library_editing,file_editing) is distinct from \
                     (coalesce($2,name),coalesce($3,description),coalesce($4,url), \
                      coalesce($5,library_editing),coalesce($6,file_editing))",
                )
                .bind(self.target.id.map(GroupId::get))
                .bind(changes.name)
                .bind(changes.description)
                .bind(changes.url)
                .bind(changes.library_editing)
                .bind(changes.file_editing)
                .execute(&mut *self.tx)
                .await?
                .rows_affected();
                (
                    None,
                    if changed == 0 {
                        AuditOutcome::Noop
                    } else {
                        AuditOutcome::Success
                    },
                )
            }
            GroupAction::Delete => {
                let group = &self.groups[0];
                let library = LibraryId::new(group.library)
                    .ok_or_else(|| sqlx::Error::Protocol("invalid group library".into()))?;
                for key in file_keys {
                    super::files::remove_file_reference(&mut self.tx, library, key).await?;
                }
                for table in [
                    "fulltext",
                    "object",
                    "setting",
                    "deletion",
                    "legacy_blob_reconciliation",
                ] {
                    sqlx::query(&format!("delete from {table} where library_id=$1"))
                        .bind(library.get())
                        .execute(&mut *self.tx)
                        .await?;
                }
                // Cascades remove only this group's memberships and explicit
                // grants. Mixed-scope keys and wildcard grants remain live.
                sqlx::query("delete from groups where id=$1")
                    .bind(group.id)
                    .execute(&mut *self.tx)
                    .await?;
                sqlx::query("delete from library where id=$1")
                    .bind(library.get())
                    .execute(&mut *self.tx)
                    .await?;
                (None, AuditOutcome::Success)
            }
            GroupAction::SetMember | GroupAction::RemoveMember | GroupAction::TransferOwner => {
                let group = &self.groups[0];
                let changed = match self.target.action {
                    GroupAction::SetMember => {
                        let role = self.target.role.ok_or_else(|| {
                            sqlx::Error::Protocol("membership role required".into())
                        })?;
                        sqlx::query(
                            "insert into group_memberships(group_id,user_id,role) values($1,$2,$3) \
                             on conflict(group_id,user_id) do update set role=excluded.role \
                             where group_memberships.role is distinct from excluded.role",
                        )
                        .bind(group.id)
                        .bind(self.target.member.map(UserId::get))
                        .bind(role.as_str())
                        .execute(&mut *self.tx)
                        .await?
                        .rows_affected() != 0
                    }
                    GroupAction::RemoveMember => {
                        // Membership FK cascades only this user's explicit group
                        // grants. Never revoke the key or its unrelated scopes.
                        sqlx::query(
                            "delete from group_memberships where group_id=$1 and user_id=$2",
                        )
                        .bind(group.id)
                        .bind(self.target.member.map(UserId::get))
                        .execute(&mut *self.tx)
                        .await?
                        .rows_affected()
                            != 0
                    }
                    GroupAction::TransferOwner => {
                        let owner = self.target.owner.ok_or_else(|| {
                            sqlx::Error::Protocol("transfer owner required".into())
                        })?;
                        if owner.get() == group.owner {
                            false
                        } else {
                            // The one-owner index is immediate; the owner FK is
                            // deferred. Demote before promotion, in one transaction.
                            sqlx::query(
                                "update group_memberships set role='admin' where group_id=$1 and user_id=$2",
                            )
                            .bind(group.id)
                            .bind(group.owner)
                            .execute(&mut *self.tx)
                            .await?;
                            sqlx::query(
                                "update group_memberships set role='owner' where group_id=$1 and user_id=$2",
                            )
                            .bind(group.id)
                            .bind(owner.get())
                            .execute(&mut *self.tx)
                            .await?;
                            sqlx::query("update groups set owner_user_id=$2 where id=$1")
                                .bind(group.id)
                                .bind(owner.get())
                                .execute(&mut *self.tx)
                                .await?;
                            true
                        }
                    }
                    GroupAction::List
                    | GroupAction::Read
                    | GroupAction::Create
                    | GroupAction::Update
                    | GroupAction::Delete => {
                        return Err(sqlx::Error::Protocol("unexpected transition".into()));
                    }
                };
                if changed {
                    sqlx::query(
                        "update groups set version=version+1,updated_at=clock_timestamp() where id=$1",
                    )
                    .bind(group.id)
                    .execute(&mut *self.tx)
                    .await?;
                }
                (
                    None,
                    if changed {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Noop
                    },
                )
            }
            GroupAction::List | GroupAction::Read => {
                return Err(sqlx::Error::Protocol("unexpected group mutation".into()));
            }
        })
    }
}
