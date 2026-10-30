use serde_json::{Map, Value};
use sqlx::{PgPool, Row};

use crate::domain::LibraryId;

use super::{guarded_version, no_change, version_map, Outcome};

/// `{itemKey: version}` for full-text content changed after `since`. The version
/// is the row's own (the library version at which it last changed), so it equals
/// the per-item download's `Last-Modified-Version` and the client skips
/// re-downloading content it already holds.
pub async fn fulltext_versions(
    pool: &PgPool,
    library_id: LibraryId,
    since: i64,
) -> sqlx::Result<Value> {
    let rows = sqlx::query(
        "select item_key, version from fulltext where library_id = $1 and version > $2",
    )
    .bind(library_id.get())
    .bind(since)
    .fetch_all(pool)
    .await?;
    Ok(version_map(rows, "item_key"))
}

/// Full-text content for one item as `(row_version, {content, indexedChars, …})`.
pub async fn fulltext_item(
    pool: &PgPool,
    library_id: LibraryId,
    item_key: &str,
) -> sqlx::Result<Option<(i64, Value)>> {
    let row = sqlx::query(
        "select content, indexed_chars, total_chars, indexed_pages, total_pages, version \
         from fulltext where library_id = $1 and item_key = $2",
    )
    .bind(library_id.get())
    .bind(item_key)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| {
        let data = serde_json::json!({
            "content": r.get::<String, _>("content"),
            "indexedChars": r.get::<i64, _>("indexed_chars"),
            "totalChars": r.get::<i64, _>("total_chars"),
            "indexedPages": r.get::<i64, _>("indexed_pages"),
            "totalPages": r.get::<i64, _>("total_pages"),
        });
        (r.get::<i64, _>("version"), data)
    }))
}

/// Store a batch of full-text content, stamping each row with the new library
/// version. Returns `(new_version, successful_map)` keyed by batch index; each
/// value carries the item `key` the client matches against to mark it synced.
pub async fn write_fulltext(
    pool: &PgPool,
    proof: super::MutationProof<'_>,
    batch: Vec<Value>,
    expected: Option<i64>,
) -> sqlx::Result<Outcome<(i64, Value)>> {
    let library_id = proof.access.library_id;
    let mut tx = pool.begin().await?;
    if super::mutation_authority::lock_mutation_authority(&mut tx, &proof)
        .await?
        .is_none()
    {
        return Ok(Outcome::Denied);
    }
    if batch.is_empty() {
        return Ok(match no_change(&mut tx, library_id, expected).await? {
            Outcome::Done(version) => Outcome::Done((version, Value::Object(Map::new()))),
            Outcome::Conflict(current) => Outcome::Conflict(current),
            Outcome::Denied => Outcome::Denied,
        });
    }
    let version = match guarded_version(&mut tx, library_id, expected).await? {
        Outcome::Done(version) => version,
        Outcome::Conflict(current) => return Ok(Outcome::Conflict(current)),
        Outcome::Denied => return Ok(Outcome::Denied),
    };
    let mut successful = Map::new();
    for (index, item) in batch.into_iter().enumerate() {
        let key = item
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let content = item
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let count = |name: &str| item.get(name).and_then(Value::as_i64).unwrap_or(0);
        sqlx::query(
            "insert into fulltext \
             (library_id, item_key, content, indexed_chars, total_chars, \
              indexed_pages, total_pages, version) \
             values ($1, $2, $3, $4, $5, $6, $7, $8) \
             on conflict (library_id, item_key) \
             do update set content = $3, indexed_chars = $4, total_chars = $5, \
                indexed_pages = $6, total_pages = $7, version = $8",
        )
        .bind(library_id.get())
        .bind(&key)
        .bind(content)
        .bind(count("indexedChars"))
        .bind(count("totalChars"))
        .bind(count("indexedPages"))
        .bind(count("totalPages"))
        .bind(version)
        .execute(&mut *tx)
        .await?;
        successful.insert(index.to_string(), serde_json::json!({ "key": key }));
    }
    tx.commit().await?;
    Ok(Outcome::Done((version, Value::Object(successful))))
}
