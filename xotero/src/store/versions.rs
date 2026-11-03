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
