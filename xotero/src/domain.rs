//! Strong identifiers shared by request resolution and persistence.

/// Database identifier for one personal or group library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibraryId(i64);

impl LibraryId {
    pub fn new(value: i64) -> Option<Self> {
        (value > 0).then_some(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

/// Database identifier for one local user.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserId(i64);

impl UserId {
    pub fn new(value: i64) -> Option<Self> {
        (value > 0).then_some(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

/// Database identifier for one user-owned API key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyId(i64);

impl ApiKeyId {
    pub fn new(value: i64) -> Option<Self> {
        (value > 0).then_some(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

/// Public identifier for one Zotero group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupId(i64);

impl GroupId {
    pub fn new(value: i64) -> Option<Self> {
        (value > 0).then_some(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

/// Durable identity and personal-library ownership resolved for one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    pub user_id: UserId,
    pub username: String,
    pub display_name: String,
    pub library_id: LibraryId,
}

/// Personal-library capabilities carried by an API key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub library: bool,
    pub notes: bool,
    pub write: bool,
    pub files: bool,
}

impl Permissions {
    /// Static keys remain a recovery path with the legacy broad read scope.
    pub fn recovery(write: bool) -> Self {
        Self {
            library: true,
            notes: true,
            write,
            files: true,
        }
    }
}

/// One fully resolved library scope used by data handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibraryAccess {
    pub library_id: LibraryId,
    pub group_id: Option<GroupId>,
    pub permissions: Permissions,
    pub is_admin: bool,
    pub file_write: bool,
}

/// Authentication result inserted into Axum request extensions.
///
/// Deliberately lacks `Debug`: `presented_key` is the raw secret that Zotero
/// expects `/keys/current` to echo, and must never enter diagnostic output.
#[derive(Clone)]
pub struct RequestContext {
    pub presented_key: String,
    pub principal: Principal,
    pub permissions: Permissions,
    /// Static recovery keys have no database row and therefore no explicit
    /// per-group grants; their legacy permissions apply to all current groups.
    pub api_key_id: Option<ApiKeyId>,
}

/// Presented browser proof, not an authorization cache. Each transaction must
/// resolve and lock its original binding again. No raw credentials or Debug.
pub struct WebSessionProof {
    pub token: [u8; 32],
    pub browser: [u8; 32],
    pub csrf: Option<[u8; 32]>,
    pub origin: String,
}

/// Management accepts either a mapped browser session or an attenuated DB key.
/// A recovery credential is deliberately not representable here.
pub enum KeyProof {
    Session(WebSessionProof),
    Database([u8; 32]),
}

#[derive(Clone, Copy)]
pub enum KeyAction {
    List,
    Create,
    Revoke,
}

impl KeyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::List => "keys.list",
            Self::Create => "keys.create",
            Self::Revoke => "keys.revoke",
        }
    }
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPermissions {
    pub library: bool,
    pub write: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndividualGroupScope {
    #[serde(rename = "groupID")]
    pub group_id: i64,
    pub library: bool,
    pub write: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupScopes {
    pub all: GroupPermissions,
    pub individual: Vec<IndividualGroupScope>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyScopes {
    pub user: Permissions,
    pub groups: GroupScopes,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateKey {
    #[serde(deserialize_with = "admin_text")]
    pub name: String,
    pub access: KeyScopes,
}

impl CreateKey {
    pub fn valid(&self) -> bool {
        let user = self.access.user;
        let groups = &self.access.groups;
        let mut ids = std::collections::BTreeSet::new();
        self.name.len() <= 255
            && (user.library || !(user.notes || user.write || user.files))
            && (groups.all.library || !groups.all.write)
            && groups.individual.iter().all(|group| {
                group.group_id > 0 && (group.library || !group.write) && ids.insert(group.group_id)
            })
    }
}

#[derive(Clone, Copy)]
pub enum AdminAction {
    List,
    Create,
    Update,
    Role,
    Link,
    Unlink,
}

impl AdminAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::List => "admin.users",
            Self::Create => "admin.create-user",
            Self::Update => "admin.update-user",
            Self::Role => "admin.set-role",
            Self::Link => "admin.link-identity",
            Self::Unlink => "authority.unlink-identity",
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateUser {
    #[serde(deserialize_with = "admin_text")]
    pub username: String,
    #[serde(deserialize_with = "admin_text")]
    pub display_name: String,
    #[serde(deserialize_with = "admin_text")]
    pub issuer: String,
    #[serde(deserialize_with = "admin_text")]
    pub subject: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateUser {
    #[serde(default, deserialize_with = "optional_admin_text")]
    pub display_name: Option<String>,
    #[serde(default, deserialize_with = "optional_bool")]
    pub disabled: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetInstanceAdmin {
    pub enabled: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIdentity {
    #[serde(deserialize_with = "admin_text")]
    pub issuer: String,
    #[serde(deserialize_with = "admin_text")]
    pub subject: String,
}

fn admin_text<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    if value.trim().is_empty() || value.contains('\0') {
        return Err(serde::de::Error::custom("nonempty text required"));
    }
    Ok(value)
}

fn optional_admin_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    admin_text(deserializer).map(Some)
}

fn optional_bool<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<bool>, D::Error> {
    <bool as serde::Deserialize>::deserialize(deserializer).map(Some)
}

/// Safe request attribution, never proof of authority. Guard validation alone
/// fills actor; later transactions still authenticate from the browser proof.
#[derive(Clone)]
pub struct AdminAudit {
    pub request_id: String,
    pub actor: Option<UserId>,
    pub subject: Option<UserId>,
}

#[derive(Clone, Copy)]
pub enum GroupAction {
    List,
    Read,
    Create,
    Update,
    Delete,
    SetMember,
    RemoveMember,
    TransferOwner,
}

impl GroupAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::List => "groups.list",
            Self::Read => "groups.read",
            Self::Create => "groups.create",
            Self::Update => "groups.update",
            Self::Delete => "groups.delete",
            Self::SetMember => "groups.set-member",
            Self::RemoveMember => "groups.remove-member",
            Self::TransferOwner => "groups.transfer-owner",
        }
    }

    pub fn mutation(self) -> bool {
        !matches!(self, Self::List | Self::Read)
    }
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(try_from = "String")]
pub enum GroupRole {
    Member,
    Admin,
}

impl TryFrom<String> for GroupRole {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "member" => Ok(Self::Member),
            "admin" => Ok(Self::Admin),
            _ => Err("member or admin string required"),
        }
    }
}

impl GroupRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
        }
    }
}

/// Extension metadata only. Ownership and membership transitions have separate
/// contracts and cannot be smuggled into a metadata patch.
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GroupChanges {
    #[serde(default, deserialize_with = "optional_admin_text")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "group_text")]
    pub description: Option<String>,
    #[serde(default, deserialize_with = "group_text")]
    pub url: Option<String>,
    #[serde(default, deserialize_with = "optional_admin_text")]
    pub library_editing: Option<String>,
    #[serde(default, deserialize_with = "optional_admin_text")]
    pub file_editing: Option<String>,
}

fn group_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    if value.contains('\0') {
        return Err(serde::de::Error::custom("invalid text"));
    }
    Ok(Some(value))
}

impl GroupChanges {
    pub fn valid(&self) -> bool {
        self.name.as_ref().is_none_or(|name| name.len() <= 255)
            && self
                .description
                .as_ref()
                .is_none_or(|text| text.chars().count() <= 1024)
            && self.url.as_ref().is_none_or(|text| text.len() <= 2048)
            && self
                .library_editing
                .as_deref()
                .is_none_or(|value| matches!(value, "members" | "admins"))
            && self
                .file_editing
                .as_deref()
                .is_none_or(|value| matches!(value, "members" | "admins" | "none"))
            && (self.name.is_some()
                || self.description.is_some()
                || self.url.is_some()
                || self.library_editing.is_some()
                || self.file_editing.is_some())
    }
}

#[derive(Clone, Copy)]
pub struct GroupTarget {
    pub admin: bool,
    pub action: GroupAction,
    pub id: Option<GroupId>,
    pub owner: Option<UserId>,
    pub member: Option<UserId>,
    pub role: Option<GroupRole>,
    pub expected: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::{ApiKeyId, GroupId, LibraryId, Permissions, UserId};

    #[test]
    fn database_ids_are_positive() {
        assert_eq!(LibraryId::new(1).map(LibraryId::get), Some(1));
        assert_eq!(LibraryId::new(0), None);
        assert_eq!(LibraryId::new(-1), None);
        assert_eq!(UserId::new(1).map(UserId::get), Some(1));
        assert_eq!(UserId::new(0), None);
        assert_eq!(UserId::new(-1), None);
        assert_eq!(ApiKeyId::new(1).map(ApiKeyId::get), Some(1));
        assert_eq!(ApiKeyId::new(0), None);
        assert_eq!(GroupId::new(1).map(GroupId::get), Some(1));
        assert_eq!(GroupId::new(0), None);
    }

    #[test]
    fn recovery_keys_preserve_legacy_read_scope() {
        assert_eq!(
            Permissions::recovery(false),
            Permissions {
                library: true,
                notes: true,
                write: false,
                files: true,
            }
        );
    }
}
