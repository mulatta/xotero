use serde_json::{Map, Value};
use sqlx::{PgPool, Row};

use crate::domain::LibraryId;

use super::{guarded_version, no_change, Outcome};

pub async fn settings(pool: &PgPool, library_id: LibraryId) -> sqlx::Result<Value> {
    let rows = sqlx::query("select key, version, value from setting where library_id = $1")
        .bind(library_id.get())
        .fetch_all(pool)
        .await?;
    let mut map = Map::new();
    for row in rows {
        let value: Value = row.get("value");
        map.insert(
            row.get("key"),
            serde_json::json!({ "value": value, "version": row.get::<i64, _>("version") }),
        );
    }
    Ok(Value::Object(map))
}

/// Store a `{key: {value}}` settings object.
pub async fn write_settings(
    pool: &PgPool,
    proof: super::MutationProof<'_>,
    body: Value,
    expected: Option<i64>,
) -> sqlx::Result<Outcome<i64>> {
    let library_id = proof.access.library_id;
    let mut tx = pool.begin().await?;
    let Some(access) = super::mutation_authority::lock_mutation_authority(&mut tx, &proof).await?
    else {
        return Ok(Outcome::Denied);
    };
    if body.as_object().is_some_and(|entries| {
        entries
            .keys()
            .any(|key| super::mutation_authority::protected_setting(access, key))
    }) {
        return Ok(Outcome::Denied);
    }
    if body.as_object().is_none_or(|m| m.is_empty()) {
        return no_change(&mut tx, library_id, expected).await;
    }
    let version = match guarded_version(&mut tx, library_id, expected).await? {
        Outcome::Done(version) => version,
        Outcome::Conflict(current) => return Ok(Outcome::Conflict(current)),
        Outcome::Denied => return Ok(Outcome::Denied),
    };
    if let Value::Object(entries) = body {
        for (key, entry) in entries {
            let value = entry.get("value").cloned().unwrap_or(entry);
            sqlx::query(
                "insert into setting (library_id, key, version, value) values ($1, $2, $3, $4) \
                 on conflict (library_id, key) do update set version = $3, value = $4",
            )
            .bind(library_id.get())
            .bind(&key)
            .bind(version)
            .bind(&value)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(Outcome::Done(version))
}

/// Delete the named settings, recording each in the deletion log so `/deleted`
/// can propagate the removal. Returns the new library version or a conflict.
pub async fn delete_settings(
    pool: &PgPool,
    proof: super::MutationProof<'_>,
    keys: &[String],
    expected: Option<i64>,
) -> sqlx::Result<Outcome<i64>> {
    let library_id = proof.access.library_id;
    let mut tx = pool.begin().await?;
    let Some(access) = super::mutation_authority::lock_mutation_authority(&mut tx, &proof).await?
    else {
        return Ok(Outcome::Denied);
    };
    if keys
        .iter()
        .any(|key| super::mutation_authority::protected_setting(access, key))
    {
        return Ok(Outcome::Denied);
    }
    if keys.is_empty() {
        return no_change(&mut tx, library_id, expected).await;
    }
    let version = match guarded_version(&mut tx, library_id, expected).await? {
        Outcome::Done(version) => version,
        Outcome::Conflict(current) => return Ok(Outcome::Conflict(current)),
        Outcome::Denied => return Ok(Outcome::Denied),
    };
    for key in keys {
        sqlx::query("delete from setting where library_id = $1 and key = $2")
            .bind(library_id.get())
            .bind(key)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "insert into deletion (library_id, kind, key, version) values ($1, 'setting', $2, $3) \
             on conflict (library_id, kind, key) do update set version = $3",
        )
        .bind(library_id.get())
        .bind(key)
        .bind(version)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Outcome::Done(version))
}
