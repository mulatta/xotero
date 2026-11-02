use crate::domain::GroupId;

/// Item keys become object keys in the bucket (and path components in URLs), so
/// reject anything that isn't a plain alphanumeric token (no `/`, `.`, `..`).
/// Zotero keys are 8 alphanumeric chars; allow a little slack.
pub(crate) fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 32 && key.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A Zotero object key: exactly 8 chars from a base32 alphabet (digits 2-9 and
/// A-Z without the ambiguous `0`/`1`/`O`). The client rejects anything else
/// ("key is not valid") and queues it, so reject a malformed key at the API
/// boundary rather than let it sync and break the client. Object keys only —
/// settings keys are arbitrary names handled on a separate path.
pub(crate) fn valid_object_key(key: &str) -> bool {
    key.len() == 8
        && key
            .bytes()
            .all(|b| b"23456789ABCDEFGHIJKLMNPQRSTUVWXYZ".contains(&b))
}

pub(crate) fn is_attachment_permission_path(path: &str) -> bool {
    let mut segments = path.split('/');
    if segments.next() != Some("") {
        return false;
    }
    let Some(scope) = segments.next() else {
        return false;
    };
    if !matches!(scope, "users" | "groups") {
        return false;
    }
    let Some(raw_id) = segments.next() else {
        return false;
    };
    if !raw_id.parse::<i64>().is_ok_and(|id| id > 0) || segments.next() != Some("items") {
        return false;
    }
    let Some(key) = segments.next() else {
        return false;
    };
    if key.is_empty() {
        return false;
    }
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ),
        (Some("file"), None, None, None) | (Some("file"), Some("view"), Some("url"), None)
    )
}

pub(crate) fn request_log_path(path: &str) -> &str {
    if path.starts_with("/uploads/") {
        "/uploads/{token}"
    } else if path.starts_with("/keys/sessions/") {
        "/keys/sessions/{token}"
    } else {
        path
    }
}

/// Schema mappings and item templates carry no library data and need no key.
pub(crate) fn is_public_metadata_path(path: &str) -> bool {
    matches!(
        path,
        "/schema"
            | "/itemTypes"
            | "/itemFields"
            | "/creatorFields"
            | "/itemTypeFields"
            | "/itemTypeCreatorTypes"
            | "/items/new"
    )
}

pub(crate) fn is_group_discovery_path(path: &str) -> bool {
    let segments: Vec<_> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    matches!(segments.as_slice(), ["groups", _] | ["users", _, "groups"])
}

pub(crate) fn path_user_id(path: &str) -> Result<Option<i64>, ()> {
    let mut segments = path.split('/');
    if segments.next() != Some("") || segments.next() != Some("users") {
        return Ok(None);
    }
    let id = segments.next().ok_or(())?.parse().map_err(|_| ())?;
    Ok(Some(id))
}

pub(crate) fn path_group_data_id(path: &str) -> Result<Option<GroupId>, ()> {
    let segments: Vec<_> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.first() != Some(&"groups") || segments.len() < 3 {
        return Ok(None);
    }
    let raw = segments[1].parse().map_err(|_| ())?;
    GroupId::new(raw).map(Some).ok_or(())
}
