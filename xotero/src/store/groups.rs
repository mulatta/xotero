use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::domain::{ApiKeyId, GroupId, LibraryAccess, LibraryId, Permissions, UserId};

pub struct GroupGrant {
    pub group_id: Option<GroupId>,
    pub library: bool,
    pub write: bool,
}

pub async fn api_key_group_grants(
    pool: &PgPool,
    api_key_id: ApiKeyId,
) -> sqlx::Result<Vec<GroupGrant>> {
    let rows = sqlx::query(
        "select null::bigint as group_id, library, write \
         from api_key_all_groups_permissions where api_key_id = $1 \
         union all \
         select group_id, library, write \
         from api_key_group_permissions where api_key_id = $1 \
         order by group_id nulls first",
    )
    .bind(api_key_id.get())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let group_id = row
                .get::<Option<i64>, _>("group_id")
                .map(|raw| {
                    GroupId::new(raw)
                        .ok_or_else(|| sqlx::Error::Protocol(format!("invalid group ID {raw}")))
                })
                .transpose()?;
            Ok(GroupGrant {
                group_id,
                library: row.get("library"),
                write: row.get("write"),
            })
        })
        .collect::<sqlx::Result<Vec<_>>>()
}

pub struct GroupMetadata {
    pub id: GroupId,
    pub version: i64,
    pub name: String,
    pub description: String,
    pub url: String,
    pub group_type: String,
    pub library_reading: String,
    pub library_editing: String,
    pub file_editing: String,
    pub owner: i64,
    pub role: String,
    pub admins: Vec<i64>,
    pub members: Vec<i64>,
    pub created: String,
    pub last_modified: String,
    pub num_items: i64,
}

fn group_metadata_from_row(row: &PgRow) -> sqlx::Result<GroupMetadata> {
    let raw_group_id = row.get::<i64, _>("id");
    let id = GroupId::new(raw_group_id)
        .ok_or_else(|| sqlx::Error::Protocol(format!("invalid group ID {raw_group_id}")))?;
    Ok(GroupMetadata {
        id,
        version: row.get("version"),
        name: row.get("name"),
        description: row.get("description"),
        url: row.get("url"),
        group_type: row.get("type"),
        library_reading: row.get("library_reading"),
        library_editing: row.get("library_editing"),
        file_editing: row.get("file_editing"),
        owner: row.get("owner"),
        role: row.get("role"),
        admins: row.get("admins"),
        members: row.get("members"),
        created: row.get("created"),
        last_modified: row.get("last_modified"),
        num_items: row.get("num_items"),
    })
}

const GROUP_METADATA_SELECT: &str = "\
    select g.id, g.library_id, g.version, g.name, g.description, g.url, g.type, \
           g.library_reading, g.library_editing, g.file_editing, \
           g.owner_user_id as owner, membership.role, \
           coalesce((select array_agg(gm.user_id order by gm.user_id) \
                     from group_memberships gm \
                     join users gu on gu.id = gm.user_id and gu.disabled_at is null \
                     where gm.group_id = g.id and gm.role = 'admin'), '{}') as admins, \
           coalesce((select array_agg(gm.user_id order by gm.user_id) \
                     from group_memberships gm \
                     join users gu on gu.id = gm.user_id and gu.disabled_at is null \
                     where gm.group_id = g.id and gm.role = 'member'), '{}') as members, \
           to_char(g.created_at at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as created, \
           to_char(g.updated_at at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as last_modified, \
           (select count(*) from object o \
            where o.library_id = g.library_id and o.kind = 'item') as num_items \
    from groups g \
    join group_memberships target_membership \
      on target_membership.group_id = g.id and target_membership.user_id = $1 \
    join users target_user \
      on target_user.id = target_membership.user_id and target_user.disabled_at is null \
    join group_memberships membership \
      on membership.group_id = g.id and membership.user_id = $2 \
    join users member_user \
      on member_user.id = membership.user_id and member_user.disabled_at is null \
    join users owner_user \
      on owner_user.id = g.owner_user_id and owner_user.disabled_at is null \
    where ( \
        $3::boolean \
        or exists (select 1 from api_key_all_groups_permissions ag \
                   where ag.api_key_id = $4 and ag.library) \
        or exists (select 1 from api_key_group_permissions eg \
                   where eg.api_key_id = $4 and eg.group_id = g.id and eg.library) \
    )";

pub async fn groups_for_user(
    pool: &PgPool,
    target_user_id: UserId,
    requesting_user_id: UserId,
    api_key_id: Option<ApiKeyId>,
    static_library_access: bool,
) -> sqlx::Result<Vec<GroupMetadata>> {
    let query = format!("{GROUP_METADATA_SELECT} order by g.id");
    let rows = sqlx::query(&query)
        .bind(target_user_id.get())
        .bind(requesting_user_id.get())
        .bind(static_library_access)
        .bind(api_key_id.map(ApiKeyId::get))
        .fetch_all(pool)
        .await?;
    rows.iter().map(group_metadata_from_row).collect()
}

pub async fn active_user_exists(pool: &PgPool, user_id: UserId) -> sqlx::Result<bool> {
    sqlx::query_scalar("select exists(select 1 from users where id = $1 and disabled_at is null)")
        .bind(user_id.get())
        .fetch_one(pool)
        .await
}

pub enum GroupLibraryResolution {
    Missing,
    Denied,
    Allowed(LibraryAccess),
}

pub async fn resolve_group_library<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    group_id: GroupId,
    user_id: UserId,
    api_key_id: Option<ApiKeyId>,
    static_permissions: Option<Permissions>,
) -> sqlx::Result<GroupLibraryResolution> {
    resolve_group_library_with_grants(
        executor,
        group_id,
        user_id,
        api_key_id,
        static_permissions,
        (true, true),
    )
    .await
}

pub(super) async fn resolve_group_library_with_grants<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    group_id: GroupId,
    user_id: UserId,
    api_key_id: Option<ApiKeyId>,
    static_permissions: Option<Permissions>,
    grant_rows: (bool, bool),
) -> sqlx::Result<GroupLibraryResolution> {
    let row = sqlx::query(
        "select g.library_id, g.library_editing, g.file_editing, membership.role, \
                coalesce(all_grant.library, false) as all_library, \
                coalesce(all_grant.write, false) as all_write, \
                coalesce(explicit_grant.library, false) as explicit_library, \
                coalesce(explicit_grant.write, false) as explicit_write, \
                coalesce(explicit_grant.policy_limited, false) as policy_limited \
         from groups g \
         join library l on l.id = g.library_id and l.kind = g.library_kind \
         join users owner_user \
           on owner_user.id = g.owner_user_id and owner_user.disabled_at is null \
         left join group_memberships membership \
           on membership.group_id = g.id and membership.user_id = $2 \
         left join api_key_all_groups_permissions all_grant \
           on all_grant.api_key_id = $3 and $4 \
         left join api_key_group_permissions explicit_grant \
           on explicit_grant.api_key_id = $3 and explicit_grant.group_id = g.id and $5 \
         where g.id = $1",
    )
    .bind(group_id.get())
    .bind(user_id.get())
    .bind(api_key_id.map(ApiKeyId::get))
    .bind(grant_rows.0)
    .bind(grant_rows.1)
    .fetch_optional(executor)
    .await?;
    let Some(row) = row else {
        return Ok(GroupLibraryResolution::Missing);
    };
    let Some(role) = row.get::<Option<String>, _>("role") else {
        return Ok(GroupLibraryResolution::Denied);
    };
    let static_library = static_permissions.is_some_and(|permissions| permissions.library);
    let static_write = static_permissions.is_some_and(|permissions| permissions.write);
    let all_library = static_library || row.get::<bool, _>("all_library");
    let all_write = static_write || row.get::<bool, _>("all_write");
    let explicit_library = row.get::<bool, _>("explicit_library");
    if !all_library && !explicit_library {
        return Ok(GroupLibraryResolution::Denied);
    }
    let policy_write = matches!(role.as_str(), "owner" | "admin")
        || (role == "member" && row.get::<String, _>("library_editing") == "members");
    let write = (explicit_library
        && row.get::<bool, _>("explicit_write")
        && (!row.get::<bool, _>("policy_limited") || policy_write))
        || (all_library && all_write && policy_write);
    let is_admin = matches!(role.as_str(), "owner" | "admin");
    let file_write = write
        && match row.get::<String, _>("file_editing").as_str() {
            "members" => true,
            "admins" => is_admin,
            _ => false,
        };
    let raw_library_id = row.get::<i64, _>("library_id");
    let library_id = LibraryId::new(raw_library_id).ok_or_else(|| {
        sqlx::Error::Protocol(format!("invalid group library ID {raw_library_id}"))
    })?;
    Ok(GroupLibraryResolution::Allowed(LibraryAccess {
        library_id,
        group_id: Some(group_id),
        permissions: Permissions {
            library: true,
            notes: true,
            write,
            files: true,
        },
        is_admin,
        file_write,
    }))
}

pub async fn group_for_user(
    pool: &PgPool,
    group_id: GroupId,
    user_id: UserId,
    api_key_id: Option<ApiKeyId>,
    static_library_access: bool,
) -> sqlx::Result<Option<GroupMetadata>> {
    let query = format!("{GROUP_METADATA_SELECT} and g.id = $5");
    let row = sqlx::query(&query)
        .bind(user_id.get())
        .bind(user_id.get())
        .bind(static_library_access)
        .bind(api_key_id.map(ApiKeyId::get))
        .bind(group_id.get())
        .fetch_optional(pool)
        .await?;
    row.as_ref().map(group_metadata_from_row).transpose()
}
