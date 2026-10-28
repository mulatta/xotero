use serde_json::{Map, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row};

use crate::domain::LibraryId;
use crate::query::{ItemQuery, QMode};

use super::{guarded_version, is_stored_file_attachment, no_change, Outcome};

fn object_json(row: PgRow) -> Value {
    serde_json::json!({
        "key": row.get::<String, _>("key"),
        "version": row.get::<i64, _>("version"),
        "data": order_fields(row.get::<Value, _>("data")),
    })
}

/// Zotero's `fromJSON` processes fields in object order and requires a
/// discriminator field first: an attachment needs `linkMode` before
/// `filename`/`path` ("Link mode must be set before setting attachment path"),
/// and an annotation needs `annotationType` before its other `annotation*` fields
/// ("annotationType must be set before other annotation properties"). jsonb
/// storage sorts keys alphabetically, putting both after their dependents, so
/// re-emit them first. Relies on serde_json's preserve_order feature.
fn order_fields(data: Value) -> Value {
    const FIRST: [&str; 2] = ["annotationType", "linkMode"];
    let Value::Object(map) = &data else {
        return data;
    };
    if !FIRST.iter().any(|k| map.contains_key(*k)) {
        return data;
    }
    let mut ordered = Map::new();
    for key in FIRST {
        if let Some(value) = map.get(key) {
            ordered.insert(key.to_string(), value.clone());
        }
    }
    for (key, value) in map {
        if !FIRST.contains(&key.as_str()) {
            ordered.insert(key.clone(), value.clone());
        }
    }
    Value::Object(ordered)
}

/// Generate a fresh Zotero object key (8 chars from the base32 alphabet) for an
/// object the client posted without one. 32 divides 256, so the byte→alphabet
/// mapping is unbiased.
fn generate_key() -> String {
    use std::io::Read;
    const ALPHABET: &[u8] = b"23456789ABCDEFGHIJKLMNPQRSTUVWXYZ";
    let mut buf = [0u8; 8];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf));
    buf.iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

/// A write either committed at a new version or was rejected because the
/// client's `If-Unmodified-Since-Version` no longer matches the library.
pub enum ObjectMutation<T> {
    Done(T),
    Conflict(i64),
    FileWriteDenied,
}

pub async fn objects(
    pool: &PgPool,
    library_id: LibraryId,
    kind: &str,
    keys: &[String],
    include_notes: bool,
) -> sqlx::Result<Value> {
    let rows = sqlx::query(
        "select key, version, data from object \
         where library_id = $1 and kind = $2 and key = any($3) \
         and ($4 or kind <> 'item' or item_type is distinct from 'note')",
    )
    .bind(library_id.get())
    .bind(kind)
    .bind(keys)
    .bind(include_notes)
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(rows.into_iter().map(object_json).collect()))
}

/// Escape LIKE/ILIKE wildcards so a search term matches literally; the `escape
/// '\'` clause in the query below makes `\` the escape character.
fn escape_like(term: &str) -> String {
    term.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Append the shared `library_id … and <filters>` predicate for an item query to
/// `sql` (binding its parameters). Used by the count, page and key queries so
/// they always filter identically. Filters compare the generated columns from
/// migration 0006 (item_type/is_top/deleted/search_text/tag_names/…), so they
/// are plain indexed comparisons rather than jsonb digging.
fn push_item_filters(
    sql: &mut QueryBuilder<Postgres>,
    library_id: LibraryId,
    q: &ItemQuery,
    include_notes: bool,
) {
    sql.push("library_id = ")
        .push_bind(library_id.get())
        .push(" and kind = 'item'");

    // Zotero's notes capability hides note items from every item search shape.
    // Annotations remain visible: upstream treats only itemType=note as scoped.
    if !include_notes {
        sql.push(" and item_type is distinct from 'note'");
    }

    // Trash handling: /items/trash returns only trashed items; otherwise trashed
    // items are excluded unless includeTrashed is set.
    if q.only_trashed {
        sql.push(" and deleted");
    } else if !q.include_trashed {
        sql.push(" and not deleted");
    }

    if let Some(term) = &q.q {
        let like = format!("%{}%", escape_like(term));
        // titleCreatorYear matches title/date/creator names via the search_text
        // column (trgm-indexed); everything also matches stored full-text content.
        // That OR spans the fulltext table, so that mode cannot use the index.
        sql.push(" and (search_text ilike ")
            .push_bind(like.clone())
            .push(" escape '\\'");
        if q.qmode == QMode::Everything {
            sql.push(
                " or exists (select 1 from fulltext f \
                 where f.library_id = object.library_id and f.item_key = object.key \
                 and f.content ilike ",
            )
            .push_bind(like.clone())
            .push(" escape '\\')");
        }
        sql.push(")");
    }

    if !q.item_type.include.is_empty() {
        sql.push(" and item_type = any(")
            .push_bind(q.item_type.include.clone())
            .push(")");
    }
    if !q.item_type.exclude.is_empty() {
        sql.push(" and item_type <> all(")
            .push_bind(q.item_type.exclude.clone())
            .push(")");
    }

    // AND across groups, OR within a group: the item must carry a tag from each
    // group, i.e. tag_names overlaps every group's alternatives.
    for group in &q.tags {
        sql.push(" and tag_names && ").push_bind(group.clone());
    }

    // /items/top: only top-level items.
    if q.top {
        sql.push(" and is_top");
    }

    // /collections/<key>/items: items whose collections contain the key.
    if let Some(key) = &q.collection {
        sql.push(" and collection_keys @> ")
            .push_bind(vec![key.clone()]);
    }
}

/// Run a CLI-facing item listing: filter, search, sort and page over the stored
/// items. Returns `([{key, version, data}], total)`, where `total` is the full
/// match count. It is counted separately from the page so it stays correct even
/// when `start` runs past the end (a window count would vanish with the rows).
pub async fn query_items(
    pool: &PgPool,
    library_id: LibraryId,
    q: &ItemQuery,
    include_notes: bool,
) -> sqlx::Result<(Vec<Value>, i64)> {
    let mut count: QueryBuilder<Postgres> = QueryBuilder::new("select count(*) from object where ");
    push_item_filters(&mut count, library_id, q, include_notes);
    let total: i64 = count.build().fetch_one(pool).await?.get(0);

    let mut sql: QueryBuilder<Postgres> =
        QueryBuilder::new("select key, version, data from object where ");
    push_item_filters(&mut sql, library_id, q, include_notes);
    // order_expr/sql() are fixed strings (no user input), so pushing them raw is
    // safe; nulls sort last so items missing the sort field don't lead.
    sql.push(" order by ")
        .push(q.sort.order_expr())
        .push(" ")
        .push(q.direction.sql())
        .push(" nulls last, key asc limit ")
        .push_bind(q.limit)
        .push(" offset ")
        .push_bind(q.start);

    let items = sql
        .build()
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(object_json)
        .collect();
    Ok((items, total))
}

/// Every item key matching the query, ordered, with no paging — the plain key
/// list the sync client's `getKeys()` consumes (e.g. the top-level items of a
/// restored collection). Shares `push_item_filters`, so `format=keys` honours
/// the same filters as the JSON listing.
pub async fn item_keys(
    pool: &PgPool,
    library_id: LibraryId,
    q: &ItemQuery,
    include_notes: bool,
) -> sqlx::Result<Vec<String>> {
    let mut sql: QueryBuilder<Postgres> = QueryBuilder::new("select key from object where ");
    push_item_filters(&mut sql, library_id, q, include_notes);
    sql.push(" order by key");
    let keys = sql
        .build()
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| row.get::<String, _>("key"))
        .collect();
    Ok(keys)
}

/// Store a batch, stamping each object with the new library version. Both `POST`
/// and `PATCH` create-or-update with **merge** semantics: each object's provided
/// top-level fields are overlaid onto the existing stored object, omitted fields
/// are kept, and an empty value clears a field. This matches the Zotero sync
/// client, which uploads only the *changed* fields of an existing object via
/// `POST` (e.g. just `lastRead` after opening an attachment) and relies on the
/// server preserving the rest — a full replace would drop `itemType`/`linkMode`
/// and corrupt the object. Returns `(new_version, successful_map)` keyed by index.
pub async fn write(
    pool: &PgPool,
    library_id: LibraryId,
    kind: &str,
    batch: Vec<Value>,
    expected: Option<i64>,
    allow_stored_file_write: bool,
) -> sqlx::Result<ObjectMutation<(i64, Value)>> {
    if batch.is_empty() {
        return Ok(match no_change(pool, library_id, expected).await? {
            Outcome::Done(version) => ObjectMutation::Done((version, Value::Object(Map::new()))),
            Outcome::Conflict(current) => ObjectMutation::Conflict(current),
        });
    }
    let mut tx = pool.begin().await?;
    let version = match guarded_version(&mut tx, library_id, expected).await? {
        Outcome::Done(version) => version,
        Outcome::Conflict(current) => return Ok(ObjectMutation::Conflict(current)),
    };

    let batch: Vec<(String, Value)> = batch
        .into_iter()
        .map(|provided| {
            let key = provided
                .get("key")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(generate_key);
            (key, provided)
        })
        .collect();
    if kind == "item" {
        let keys: Vec<&str> = batch.iter().map(|(key, _)| key.as_str()).collect();
        super::files::lock_file_references(&mut tx, library_id, &keys).await?;
    }
    let mut successful = Map::new();
    for (index, (key, provided)) in batch.into_iter().enumerate() {
        // Start from the existing object (read in this txn so the version guard
        // serialises it) and overlay the provided top-level fields; a new key has
        // nothing to merge into, so the provided object is stored as-is.
        let existing =
            sqlx::query("select data from object where library_id = $1 and kind = $2 and key = $3")
                .bind(library_id.get())
                .bind(kind)
                .bind(&key)
                .fetch_optional(&mut *tx)
                .await?
                .map(|row| row.get::<Value, _>("data"));
        let existing_is_stored_file = existing.as_ref().is_some_and(is_stored_file_attachment);
        let mut object = match (existing, &provided) {
            (Some(Value::Object(mut base)), Value::Object(fields)) => {
                for (k, v) in fields {
                    base.insert(k.clone(), v.clone());
                }
                Value::Object(base)
            }
            _ => provided,
        };
        if let Value::Object(fields) = &mut object {
            fields.insert("key".into(), Value::from(key.clone()));
            fields.insert("version".into(), Value::from(version));
        }
        let object_is_stored_file = is_stored_file_attachment(&object);
        if kind == "item"
            && !allow_stored_file_write
            && (existing_is_stored_file || object_is_stored_file)
        {
            return Ok(ObjectMutation::FileWriteDenied);
        }
        sqlx::query(
            "insert into object (library_id, kind, key, version, data) \
             values ($1, $2, $3, $4, $5) \
             on conflict (library_id, kind, key) \
             do update set version = $4, data = $5",
        )
        .bind(library_id.get())
        .bind(kind)
        .bind(&key)
        .bind(version)
        .bind(&object)
        .execute(&mut *tx)
        .await?;
        if kind == "item" && !(existing_is_stored_file && object_is_stored_file) {
            // File metadata is valid only while one stored attachment identity
            // remains continuous. Reusing a deleted or converted key must not
            // resurrect bytes registered for its previous identity.
            super::files::remove_file_reference(&mut tx, library_id, &key).await?;
        }
        sqlx::query("delete from deletion where library_id = $1 and kind = $2 and key = $3")
            .bind(library_id.get())
            .bind(kind)
            .bind(&key)
            .execute(&mut *tx)
            .await?;
        successful.insert(
            index.to_string(),
            serde_json::json!({ "key": key, "version": version, "data": order_fields(object) }),
        );
    }
    tx.commit().await?;
    Ok(ObjectMutation::Done((version, Value::Object(successful))))
}

/// Delete objects of `kind`, recording them in the deletion log.
pub async fn delete(
    pool: &PgPool,
    library_id: LibraryId,
    kind: &str,
    keys: &[String],
    expected: Option<i64>,
    allow_stored_file_write: bool,
) -> sqlx::Result<ObjectMutation<i64>> {
    if keys.is_empty() {
        return Ok(match no_change(pool, library_id, expected).await? {
            Outcome::Done(version) => ObjectMutation::Done(version),
            Outcome::Conflict(current) => ObjectMutation::Conflict(current),
        });
    }
    let mut tx = pool.begin().await?;
    let version = match guarded_version(&mut tx, library_id, expected).await? {
        Outcome::Done(version) => version,
        Outcome::Conflict(current) => return Ok(ObjectMutation::Conflict(current)),
    };
    if kind == "item" {
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        super::files::lock_file_references(&mut tx, library_id, &keys).await?;
    }
    for key in keys {
        if kind == "item" && !allow_stored_file_write {
            let data: Option<Value> = sqlx::query_scalar(
                "select data from object where library_id = $1 and kind = $2 and key = $3",
            )
            .bind(library_id.get())
            .bind(kind)
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?;
            if data.as_ref().is_some_and(is_stored_file_attachment) {
                return Ok(ObjectMutation::FileWriteDenied);
            }
        }
        sqlx::query("delete from object where library_id = $1 and kind = $2 and key = $3")
            .bind(library_id.get())
            .bind(kind)
            .bind(key)
            .execute(&mut *tx)
            .await?;
        if kind == "item" {
            super::files::remove_file_reference(&mut tx, library_id, key).await?;
        }
        sqlx::query(
            "insert into deletion (library_id, kind, key, version) values ($1, $2, $3, $4) \
             on conflict (library_id, kind, key) do update set version = $4",
        )
        .bind(library_id.get())
        .bind(kind)
        .bind(key)
        .bind(version)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(ObjectMutation::Done(version))
}
