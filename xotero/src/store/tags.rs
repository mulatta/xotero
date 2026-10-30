use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::domain::LibraryId;

use super::{guarded_version, no_change, Outcome};

/// Distinct tags across non-trashed items with their item counts, as
/// `[{tag, numItems}]` ordered by tag. Backs the CLI-facing `/tags` listing.
pub async fn tags(pool: &PgPool, library_id: LibraryId) -> sqlx::Result<Value> {
    // Upstream treats /tags as library metadata rather than an item search, so
    // note-only tags and their linked-item counts are not notes-filtered.
    // Unnest the generated tag_names column (already guards malformed data).
    let rows = sqlx::query(
        "select tag, count(*) as num \
         from object, unnest(tag_names) as tag \
         where library_id = $1 and kind = 'item' and not deleted \
         group by tag \
         order by tag",
    )
    .bind(library_id.get())
    .fetch_all(pool)
    .await?;
    let array = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "tag": row.get::<String, _>("tag"),
                "numItems": row.get::<i64, _>("num"),
            })
        })
        .collect();
    Ok(Value::Array(array))
}

/// Delete tags library-wide: strip each tag from every item that carries it
/// (bumping those items to the new version) and record the tag in the deletion
/// log so `/deleted` propagates the removal. A tag has no object of its own, so
/// an orphaned tag with zero items still needs its deletion-log entry for
/// clients to purge it — the deletion is recorded regardless of matches.
/// Returns the new library version or a conflict.
pub async fn delete_tags(
    pool: &PgPool,
    proof: super::MutationProof<'_>,
    tags: &[String],
    expected: Option<i64>,
) -> sqlx::Result<Outcome<i64>> {
    let library_id = proof.access.library_id;
    let mut tx = pool.begin().await?;
    if super::mutation_authority::lock_mutation_authority(&mut tx, &proof)
        .await?
        .is_none()
    {
        return Ok(Outcome::Denied);
    }
    if tags.is_empty() {
        return no_change(&mut tx, library_id, expected).await;
    }
    let version = match guarded_version(&mut tx, library_id, expected).await? {
        Outcome::Done(version) => version,
        Outcome::Conflict(current) => return Ok(Outcome::Conflict(current)),
        Outcome::Denied => return Ok(Outcome::Denied),
    };
    for tag in tags {
        // Drop the matching entry from each item's data.tags array; the
        // tag_names generated column and its index update automatically.
        sqlx::query(
            "update object set version = $3, data = jsonb_set(data, '{tags}', coalesce((\
                 select jsonb_agg(t) \
                 from jsonb_array_elements(data->'tags') t \
                 where t->>'tag' is distinct from $2\
             ), '[]'::jsonb)) \
             where library_id = $1 and kind = 'item' and tag_names @> array[$2]",
        )
        .bind(library_id.get())
        .bind(tag)
        .bind(version)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "insert into deletion (library_id, kind, key, version) values ($1, 'tag', $2, $3) \
             on conflict (library_id, kind, key) do update set version = $3",
        )
        .bind(library_id.get())
        .bind(tag)
        .bind(version)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Outcome::Done(version))
}
