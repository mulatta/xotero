use serde_json::{Map, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::domain::LibraryId;

/// `{<key_col>: version}` map from version-listing rows (the `format=versions`
/// shape shared by objects, top items and full-text).
pub(crate) fn version_map(rows: Vec<PgRow>, key_col: &str) -> Value {
    let mut map = Map::new();
    for row in rows {
        map.insert(row.get(key_col), Value::from(row.get::<i64, _>("version")));
    }
    Value::Object(map)
}

pub async fn current_version(pool: &PgPool, library_id: LibraryId) -> sqlx::Result<i64> {
    let row = sqlx::query("select version from library where id = $1")
        .bind(library_id.get())
        .fetch_one(pool)
        .await?;
    Ok(row.get("version"))
}

/// `{key: version}` for objects of `kind` changed after `since`.
pub async fn versions(
    pool: &PgPool,
    library_id: LibraryId,
    kind: &str,
    since: i64,
    include_notes: bool,
) -> sqlx::Result<Value> {
    let rows = sqlx::query(
        "select key, version from object \
         where library_id = $1 and kind = $2 and version > $3 \
         and ($4 or kind <> 'item' or item_type is distinct from 'note')",
    )
    .bind(library_id.get())
    .bind(kind)
    .bind(since)
    .bind(include_notes)
    .fetch_all(pool)
    .await?;
    Ok(version_map(rows, "key"))
}

/// `{key: version}` for top-level items changed after `since`. The client's
/// sync fetches top-level items first (a parent-first phase), so this is the
/// top-filtered counterpart of `versions(pool, library_id, "item", since)`.
pub async fn top_versions(
    pool: &PgPool,
    library_id: LibraryId,
    since: i64,
    include_notes: bool,
) -> sqlx::Result<Value> {
    let rows = sqlx::query(
        "select key, version from object \
         where library_id = $1 and kind = 'item' and is_top and version > $2 \
         and ($3 or item_type is distinct from 'note')",
    )
    .bind(library_id.get())
    .bind(since)
    .bind(include_notes)
    .fetch_all(pool)
    .await?;
    Ok(version_map(rows, "key"))
}

/// Deleted object keys after `since`, grouped by kind for the /deleted endpoint.
pub async fn deleted(pool: &PgPool, library_id: LibraryId, since: i64) -> sqlx::Result<Value> {
    let rows = sqlx::query("select kind, key from deletion where library_id = $1 and version > $2")
        .bind(library_id.get())
        .bind(since)
        .fetch_all(pool)
        .await?;
    let (mut collections, mut searches, mut items, mut settings, mut tags) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for row in rows {
        let key: String = row.get("key");
        match row.get::<String, _>("kind").as_str() {
            "collection" => collections.push(Value::from(key)),
            "search" => searches.push(Value::from(key)),
            "setting" => settings.push(Value::from(key)),
            "tag" => tags.push(Value::from(key)),
            _ => items.push(Value::from(key)),
        }
    }
    Ok(serde_json::json!({
        "collections": collections,
        "searches": searches,
        "items": items,
        "settings": settings,
        "tags": tags,
    }))
}
