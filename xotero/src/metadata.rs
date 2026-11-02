//! Public Zotero mapping data and new-item templates.
//!
//! Everything derives from the pinned `schema.json`, embedded at compile time.
//! Shapes, ordering, fallbacks, and error messages follow dataserver's
//! `MappingsController`, so clients see what api.zotero.org returns.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;
use serde_json::{json, Map, Value};

pub(crate) const SCHEMA_JSON: &[u8] = include_bytes!(env!("XOTERO_SCHEMA"));

pub(crate) static SCHEMA: LazyLock<Schema> = LazyLock::new(|| {
    serde_json::from_slice(SCHEMA_JSON).expect("embedded Zotero schema must parse")
});

const DEFAULT_LOCALE: &str = "en-US";
const LINK_MODES: [&str; 5] = [
    "imported_file",
    "imported_url",
    "linked_file",
    "linked_url",
    "embedded_image",
];
const ANNOTATION_TYPES: [&str; 6] = ["highlight", "note", "image", "ink", "underline", "text"];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Schema {
    pub(crate) version: u64,
    item_types: Vec<ItemType>,
    locales: HashMap<String, Strings>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItemType {
    item_type: String,
    fields: Vec<Field>,
    creator_types: Vec<CreatorType>,
}

#[derive(Deserialize)]
struct Field {
    field: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatorType {
    creator_type: String,
    #[serde(default)]
    primary: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Strings {
    item_types: HashMap<String, String>,
    fields: HashMap<String, String>,
    creator_types: HashMap<String, String>,
}

/// A request the mapping endpoints reject with 400 and this message.
#[derive(Debug, PartialEq)]
pub(crate) struct Invalid(pub(crate) String);

fn localized<'a>(strings: &'a HashMap<String, String>, name: &'a str) -> &'a str {
    strings.get(name).map_or(name, String::as_str)
}

/// `{prop, localized}` rows sorted by byte order of the localized string, as
/// PHP `strcmp` does. The sort is stable, so ties keep schema order.
fn sorted_rows<'a>(prop: &str, rows: impl Iterator<Item = (&'a str, &'a str)>) -> Value {
    let mut rows: Vec<_> = rows.collect();
    rows.sort_by(|a, b| a.1.as_bytes().cmp(b.1.as_bytes()));
    rows.into_iter()
        .map(|(name, text)| json!({ prop: name, "localized": text }))
        .collect()
}

impl Schema {
    /// Exact match, then the bare language, then a regional variant of the
    /// language (en-US, then the language's own region, then by region), else
    /// en-US. An unknown locale is never an error.
    pub(crate) fn resolve_locale<'a>(&'a self, requested: Option<&'a str>) -> &'a str {
        let Some(requested) = requested.filter(|locale| !locale.is_empty()) else {
            return DEFAULT_LOCALE;
        };
        if self.locales.contains_key(requested) {
            return requested;
        }
        let language = requested.get(..2).unwrap_or(requested);
        if self.locales.contains_key(language) {
            return language;
        }
        let region = |locale: &str| locale.get(3..5).unwrap_or("").to_owned();
        self.locales
            .keys()
            .filter(|locale| locale.get(..2) == Some(language))
            .min_by_key(|locale| {
                (
                    locale.as_str() != DEFAULT_LOCALE,
                    region(locale).to_lowercase() != language,
                    region(locale),
                )
            })
            .map_or(DEFAULT_LOCALE, String::as_str)
    }

    fn strings(&self, locale: Option<&str>) -> &Strings {
        let locale = self.resolve_locale(locale);
        self.locales
            .get(locale)
            .or_else(|| self.locales.get(DEFAULT_LOCALE))
            .expect("schema provides en-US strings")
    }

    fn item_type(&self, name: &str) -> Option<&ItemType> {
        self.item_types.iter().find(|t| t.item_type == name)
    }

    /// The type a mapping endpoint describes. Annotations have no mappings.
    fn mapped_type(&self, name: Option<&str>) -> Result<&ItemType, Invalid> {
        let name = name
            .filter(|name| !name.is_empty())
            .ok_or_else(|| Invalid("'itemType' not provided".into()))?;
        self.item_type(name)
            .filter(|t| t.item_type != "annotation")
            .ok_or_else(|| Invalid(format!("Invalid item type '{name}'")))
    }

    /// Every type except attachments and annotations, which clients create
    /// through their own flows.
    pub(crate) fn item_types_list(&self, locale: Option<&str>) -> Value {
        let strings = &self.strings(locale).item_types;
        sorted_rows(
            "itemType",
            self.item_types
                .iter()
                .filter(|t| !matches!(t.item_type.as_str(), "attachment" | "annotation"))
                .map(|t| (t.item_type.as_str(), localized(strings, &t.item_type))),
        )
    }

    /// Each field some type lists, once. Base-only fields never appear.
    pub(crate) fn item_fields(&self, locale: Option<&str>) -> Value {
        let strings = &self.strings(locale).fields;
        let mut seen = std::collections::HashSet::new();
        sorted_rows(
            "field",
            self.item_types
                .iter()
                .flat_map(|t| &t.fields)
                .filter(|f| seen.insert(f.field.as_str()))
                .map(|f| (f.field.as_str(), localized(strings, &f.field))),
        )
    }

    /// The type's fields in schema order.
    pub(crate) fn item_type_fields(
        &self,
        name: Option<&str>,
        locale: Option<&str>,
    ) -> Result<Value, Invalid> {
        let item_type = self.mapped_type(name)?;
        let strings = &self.strings(locale).fields;
        Ok(item_type
            .fields
            .iter()
            .map(|f| json!({ "field": f.field, "localized": localized(strings, &f.field) }))
            .collect())
    }

    /// The primary creator type first, the rest by localized name.
    pub(crate) fn item_type_creator_types(
        &self,
        name: Option<&str>,
        locale: Option<&str>,
    ) -> Result<Value, Invalid> {
        let item_type = self.mapped_type(name)?;
        let strings = &self.strings(locale).creator_types;
        let row = |c: &CreatorType| json!({ "creatorType": c.creator_type, "localized": localized(strings, &c.creator_type) });
        let mut rows: Vec<Value> = item_type
            .creator_types
            .iter()
            .filter(|c| c.primary)
            .map(row)
            .collect();
        let Value::Array(rest) = sorted_rows(
            "creatorType",
            item_type
                .creator_types
                .iter()
                .filter(|c| !c.primary)
                .map(|c| (c.creator_type.as_str(), localized(strings, &c.creator_type))),
        ) else {
            unreachable!("sorted_rows builds an array");
        };
        rows.extend(rest);
        Ok(Value::Array(rows))
    }

    /// The new-item template for `GET /items/new`, with dataserver's key order.
    pub(crate) fn template(
        &self,
        item_type: Option<&str>,
        link_mode: Option<&str>,
        annotation_type: Option<&str>,
    ) -> Result<Value, Invalid> {
        let name = item_type
            .filter(|name| !name.is_empty())
            .ok_or_else(|| Invalid("'itemType' not provided".into()))?;
        let link_mode = if name == "attachment" {
            let mode = link_mode
                .filter(|mode| !mode.is_empty())
                .ok_or_else(|| Invalid("linkMode required for itemType=attachment".into()))?;
            if !LINK_MODES.contains(&mode) {
                return Err(Invalid(format!("Invalid linkMode '{mode}'")));
            }
            Some(mode)
        } else {
            None
        };
        let annotation_type = if name == "annotation" {
            let kind = annotation_type
                .filter(|kind| !kind.is_empty())
                .ok_or_else(|| Invalid("annotationType required for itemType=annotation".into()))?;
            if !ANNOTATION_TYPES.contains(&kind) {
                return Err(Invalid(format!("Invalid annotationType '{kind}'")));
            }
            Some(kind)
        } else {
            None
        };
        let schema_type = self
            .item_type(name)
            .ok_or_else(|| Invalid(format!("Invalid item type '{name}'")))?;

        let embedded_image = link_mode == Some("embedded_image");
        let mut json = Map::new();
        json.insert("itemType".into(), name.into());
        if let Some(mode) = link_mode {
            json.insert("linkMode".into(), mode.into());
        }
        let primary = schema_type.creator_types.iter().find(|c| c.primary);
        let mut first = true;
        for field in &schema_type.fields {
            if link_mode.is_some_and(|mode| field.field == "url" && !mode.ends_with("_url")) {
                continue;
            }
            json.insert(field.field.clone(), "".into());
            if first && name != "note" && name != "attachment" {
                if let Some(primary) = primary {
                    json.insert(
                        "creators".into(),
                        json!([{ "creatorType": primary.creator_type, "firstName": "", "lastName": "" }]),
                    );
                }
                first = false;
            }
        }
        if embedded_image {
            json.insert("parentItem".into(), "".into());
        } else if let Some(kind) = annotation_type {
            json.insert("parentItem".into(), "".into());
            json.insert("annotationType".into(), kind.into());
            if matches!(kind, "highlight" | "underline") {
                json.insert("annotationText".into(), "".into());
            }
            for key in [
                "annotationComment",
                "annotationColor",
                "annotationPageLabel",
            ] {
                json.insert(key.into(), "".into());
            }
            json.insert("annotationSortIndex".into(), "00000|000000|00000".into());
            let mut position = match kind {
                "ink" => json!({ "pageIndex": 0, "paths": [], "width": 2 }),
                _ => json!({ "pageIndex": 0, "rects": [] }),
            };
            if kind == "image" {
                position["width"] = 0.into();
                position["height"] = 0.into();
            }
            json.insert("annotationPosition".into(), position);
        }
        if name == "note" || name == "attachment" {
            json.insert("note".into(), "".into());
        }
        json.insert("tags".into(), json!([]));
        json.insert("collections".into(), json!([]));
        json.insert("relations".into(), json!({}));
        if let Some(mode) = link_mode {
            json.insert("contentType".into(), "".into());
            json.insert("charset".into(), "".into());
            if mode == "linked_file" {
                json.insert("path".into(), "".into());
            }
            if mode.starts_with("imported_") || embedded_image {
                json.insert("filename".into(), "".into());
                json.insert("md5".into(), Value::Null);
                json.insert("mtime".into(), Value::Null);
            }
            if embedded_image {
                for key in [
                    "title",
                    "url",
                    "accessDate",
                    "tags",
                    "collections",
                    "relations",
                    "note",
                    "charset",
                ] {
                    json.shift_remove(key);
                }
            }
        } else if annotation_type.is_some() {
            json.shift_remove("collections");
            json.shift_remove("relations");
        }
        Ok(Value::Object(json))
    }
}

/// Creator name parts. dataserver hard-codes these and ignores the locale.
pub(crate) fn creator_fields() -> Value {
    json!([
        { "field": "firstName", "localized": "First" },
        { "field": "lastName", "localized": "Last" },
        { "field": "name", "localized": "Name" },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(value: &Value) -> Vec<&str> {
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn locales_resolve_like_dataserver() {
        for (requested, expected) in [
            (None, "en-US"),
            (Some(""), "en-US"),
            (Some("fr-FR"), "fr-FR"),
            (Some("de"), "de"),
            (Some("fr"), "fr-FR"),
            (Some("en-AU"), "en-US"),
            (Some("xx-YY"), "en-US"),
        ] {
            assert_eq!(SCHEMA.resolve_locale(requested), expected, "{requested:?}");
        }
    }

    #[test]
    fn book_template_places_creators_after_the_first_field() {
        let template = SCHEMA.template(Some("book"), None, None).unwrap();
        assert_eq!(
            &keys(&template)[..4],
            ["itemType", "title", "creators", "abstractNote"]
        );
        assert_eq!(
            &keys(&template)[keys(&template).len() - 3..],
            ["tags", "collections", "relations"]
        );
        assert_eq!(
            template["creators"],
            json!([{ "creatorType": "author", "firstName": "", "lastName": "" }])
        );
    }

    #[test]
    fn template_rejects_missing_or_unknown_parameters() {
        for (item_type, link_mode, annotation_type, message) in [
            (None, None, None, "'itemType' not provided"),
            (Some("nope"), None, None, "Invalid item type 'nope'"),
            (
                Some("attachment"),
                None,
                None,
                "linkMode required for itemType=attachment",
            ),
            (
                Some("attachment"),
                Some("nope"),
                None,
                "Invalid linkMode 'nope'",
            ),
            (
                Some("annotation"),
                None,
                None,
                "annotationType required for itemType=annotation",
            ),
            (
                Some("annotation"),
                None,
                Some("nope"),
                "Invalid annotationType 'nope'",
            ),
        ] {
            assert_eq!(
                SCHEMA.template(item_type, link_mode, annotation_type),
                Err(Invalid(message.into()))
            );
        }
    }

    #[test]
    fn mapping_lists_exclude_annotations() {
        assert_eq!(
            SCHEMA.item_type_fields(Some("annotation"), None),
            Err(Invalid("Invalid item type 'annotation'".into()))
        );
        assert_eq!(
            SCHEMA.item_type_creator_types(Some("note"), None),
            Ok(json!([]))
        );
        let types = SCHEMA.item_types_list(None);
        let names: Vec<_> = types
            .as_array()
            .unwrap()
            .iter()
            .map(|t| &t["itemType"])
            .collect();
        assert!(names.contains(&&json!("note")));
        assert!(!names.contains(&&json!("attachment")));
        assert!(!names.contains(&&json!("annotation")));
    }
}
