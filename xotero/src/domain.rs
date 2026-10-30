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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
