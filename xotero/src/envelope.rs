//! Upstream object envelopes: the `{key, version, library, links, meta, data}`
//! wrapper dataserver puts around each object in a JSON listing.

use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryKind {
    User,
    Group,
}

/// The library an envelope names: a user's personal library (named after the
/// user) or a group (named after the group).
#[derive(Debug, Clone)]
pub struct Library {
    pub kind: LibraryKind,
    /// The user id or group id, as in the API path.
    pub id: i64,
    pub name: String,
}

impl Library {
    /// `links.alternate` is omitted: it names the zotero.org website, which
    /// xotero does not have.
    pub fn json(&self) -> Value {
        let kind = match self.kind {
            LibraryKind::User => "user",
            LibraryKind::Group => "group",
        };
        json!({"type": kind, "id": self.id, "name": self.name})
    }

    /// `<base>/users/<id>/items` or `<base>/groups/<id>/items`.
    pub fn items_url(&self, base: &str) -> String {
        let prefix = match self.kind {
            LibraryKind::User => "users",
            LibraryKind::Group => "groups",
        };
        format!("{base}/{prefix}/{}/items", self.id)
    }
}

/// Non-trashed children of one item, by kind.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Children {
    pub notes: i64,
    pub attachments: i64,
    pub annotations: i64,
}

fn json_link(href: String) -> Value {
    json!({"href": href, "type": "application/json"})
}

/// Upstream `Zotero_Item::toJSON` envelope for one item. `primary` is the
/// item type's primary creator type from the schema. Group
/// `createdByUser`/`lastModifiedByUser` and the file links (`attachment`,
/// `enclosure`) are not emitted.
pub fn item(
    library: &Library,
    base: &str,
    version: i64,
    data: Value,
    children: Children,
    can_read_notes: bool,
    primary: Option<&str>,
) -> Value {
    let field = |name: &str| data.get(name).and_then(Value::as_str).unwrap_or("");
    let key = field("key").to_string();
    let item_type = field("itemType");
    let items_url = library.items_url(base);

    let mut links = Map::new();
    links.insert("self".into(), json_link(format!("{items_url}/{key}")));
    let parent = field("parentItem");
    if !parent.is_empty() {
        links.insert("up".into(), json_link(format!("{items_url}/{parent}")));
    }

    let mut meta = Map::new();
    match item_type {
        "note" => {
            meta.insert("numChildren".into(), children.attachments.into());
        }
        // Annotations depend on note access.
        "attachment" if field("contentType") == "application/pdf" && can_read_notes => {
            meta.insert("numChildren".into(), children.annotations.into());
        }
        "attachment" | "annotation" => {}
        _ => {
            let summary = creator_summary(&data, primary);
            if !summary.is_empty() {
                meta.insert("creatorSummary".into(), summary.into());
            }
            if let Some(date) = parsed_date(field("date")) {
                meta.insert("parsedDate".into(), date.into());
            }
            let notes = if can_read_notes { children.notes } else { 0 };
            meta.insert("numChildren".into(), (notes + children.attachments).into());
        }
    }

    json!({
        "key": key,
        "version": version,
        "library": library.json(),
        "links": links,
        "meta": meta,
        "data": data,
    })
}

/// Upstream `getCreatorSummary`: the first creator type among primary, editor
/// and contributor that the item uses, summarized from up to three of them.
pub fn creator_summary(data: &Value, primary: Option<&str>) -> String {
    let creators = data
        .get("creators")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    // Single-field creators store their whole name in `name`.
    let last_name = |creator: &Value| {
        ["lastName", "name"]
            .iter()
            .find_map(|field| creator.get(*field).and_then(Value::as_str))
            .unwrap_or("")
            .to_string()
    };
    for creator_type in [primary, Some("editor"), Some("contributor")]
        .into_iter()
        .flatten()
    {
        let found: Vec<&Value> = creators
            .iter()
            .filter(|c| c.get("creatorType").and_then(Value::as_str) == Some(creator_type))
            .take(3)
            .collect();
        match found.as_slice() {
            [] => continue,
            [one] => return last_name(one),
            [a, b] => return format!("{} and {}", last_name(a), last_name(b)),
            [first, ..] => return format!("{} et al.", last_name(first)),
        }
    }
    String::new()
}

/// A run of digits split by one repeated separator, such as `2006-11-03` or
/// `11/03/2006`, as upstream's `slashRE` reads it.
fn numeric_parts(token: &str) -> Option<Vec<&str>> {
    let sep = token.chars().find(|c| matches!(c, '-' | '/' | '.'));
    let parts: Vec<&str> = match sep {
        Some(sep) => token.split(sep).collect(),
        None => vec![token],
    };
    let digits = |p: &&str| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit());
    let lengths_ok = match parts.as_slice() {
        [a] => a.len() <= 4,
        [a, b] => a.len() <= 4 && b.len() <= 2,
        [a, b, c] => a.len() <= 4 && b.len() <= 2 && c.len() <= 4,
        _ => false,
    };
    (lengths_ok && parts.iter().all(digits)).then_some(parts)
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Upstream `strToDate` as (year, month, day), en-US. The numeric form is read
/// big-endian when its first part has 3–4 digits and month-first otherwise.
fn str_to_date(input: &str) -> (Option<u32>, Option<u32>, Option<u32>) {
    let text = input.split_whitespace().collect::<Vec<_>>().join(" ");
    let words: Vec<&str> = text
        .split(' ')
        .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .filter(|w| !w.is_empty())
        .collect();

    // A numeric date is used when all three parts are present or when it is
    // the whole field.
    let numeric = words.iter().enumerate().find_map(|(i, word)| {
        let parts = numeric_parts(word)?;
        (parts.len() == 3 || (words.len() == 1 && text == *word)).then_some((i, parts))
    });
    let mut used = Vec::new();
    let (mut year, mut month, mut day) = (None, None, None);
    if let Some((i, parts)) = numeric {
        let num = |p: Option<&&str>| p.and_then(|p| p.parse::<u32>().ok());
        let (y, mut m, mut d) = if parts[0].len() >= 3 {
            (num(parts.first()), num(parts.get(1)), num(parts.get(2)))
        } else {
            (num(parts.get(2)), num(parts.first()), num(parts.get(1)))
        };
        if m.is_some_and(|m| m > 12) {
            std::mem::swap(&mut m, &mut d);
        }
        if m.is_none_or(|m| m <= 12) && d.is_none_or(|d| d <= 31) {
            used.push(i);
            (year, month, day) = (y, m, d);
        }
    }

    let unused = |used: &Vec<usize>| {
        words
            .iter()
            .enumerate()
            .filter(|(i, _)| !used.contains(i))
            .map(|(i, w)| (i, *w))
            .collect::<Vec<_>>()
    };
    if year.is_none() {
        if let Some((i, w)) = unused(&used)
            .into_iter()
            .find(|(_, w)| (3..=4).contains(&w.len()) && w.chars().all(|c| c.is_ascii_digit()))
        {
            used.push(i);
            year = w.parse().ok();
        }
    }
    if month.is_none() {
        if let Some((i, m)) = unused(&used).into_iter().find_map(|(i, w)| {
            let lower = w.to_ascii_lowercase();
            MONTHS
                .iter()
                .position(|m| lower.starts_with(m))
                .map(|m| (i, m as u32 + 1))
        }) {
            used.push(i);
            month = Some(m);
        }
    }
    if day.is_none() {
        day = unused(&used).into_iter().find_map(|(_, w)| {
            let digits = w.trim_end_matches(['s', 't', 'n', 'd', 'r', 'h']);
            let suffix = &w[digits.len()..];
            let ok = (1..=2).contains(&digits.len())
                && digits.chars().all(|c| c.is_ascii_digit())
                && ["", "st", "nd", "rd", "th"].contains(&suffix);
            ok.then(|| digits.parse::<u32>().ok())
                .flatten()
                .filter(|d| *d <= 31)
        });
    }
    (year, month, day)
}

/// Upstream `meta.parsedDate`: `strToMultipart`, then `sqlToISO8601`, which
/// drops the parts that are unknown. `None` without a year.
pub fn parsed_date(date: &str) -> Option<String> {
    let (year, month, day) = str_to_date(date);
    let year = year.filter(|y| (1..=9999).contains(y))?;
    let mut out = format!("{year:04}");
    if let Some(month) = month.filter(|m| (1..=12).contains(m)) {
        out.push_str(&format!("-{month:02}"));
        if let Some(day) = day.filter(|d| (1..=31).contains(d)) {
            out.push_str(&format!("-{day:02}"));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alice() -> Library {
        Library {
            kind: LibraryKind::User,
            id: 101,
            name: "Alice".into(),
        }
    }

    #[test]
    fn library_json_names_owner() {
        assert_eq!(
            alice().json(),
            json!({"type": "user", "id": 101, "name": "Alice"})
        );
        let group = Library {
            kind: LibraryKind::Group,
            id: 303,
            name: "Research group".into(),
        };
        assert_eq!(
            group.json(),
            json!({"type": "group", "id": 303, "name": "Research group"})
        );
        assert_eq!(group.items_url("B"), "B/groups/303/items");
    }

    fn author(last: &str) -> serde_json::Value {
        json!({"creatorType": "author", "firstName": "X", "lastName": last})
    }

    #[test]
    fn creator_summary_follows_upstream() {
        let summary = |creators: serde_json::Value| {
            creator_summary(&json!({"creators": creators}), Some("author"))
        };
        assert_eq!(summary(json!([author("Lovelace")])), "Lovelace");
        assert_eq!(
            summary(json!([author("Turing"), author("Hopper")])),
            "Turing and Hopper"
        );
        assert_eq!(
            summary(json!([
                author("Knuth"),
                author("Dijkstra"),
                author("Hoare")
            ])),
            "Knuth et al."
        );
        // Editors stand in when no primary creator exists, then contributors.
        assert_eq!(
            summary(json!([
                {"creatorType": "contributor", "lastName": "C"},
                {"creatorType": "editor", "lastName": "E"}
            ])),
            "E"
        );
        // Single-field creators carry `name`.
        assert_eq!(
            summary(json!([{"creatorType": "author", "name": "ACM"}])),
            "ACM"
        );
        assert_eq!(summary(json!([])), "");
    }

    #[test]
    fn parsed_date_keeps_known_precision() {
        assert_eq!(parsed_date("1843").as_deref(), Some("1843"));
        assert_eq!(parsed_date("2006-11-03").as_deref(), Some("2006-11-03"));
        assert_eq!(parsed_date("2006-11").as_deref(), Some("2006-11"));
        assert_eq!(parsed_date("11/03/2006").as_deref(), Some("2006-11-03"));
        assert_eq!(
            parsed_date("November 3rd, 2006").as_deref(),
            Some("2006-11-03")
        );
        assert_eq!(parsed_date("March 1999").as_deref(), Some("1999-03"));
        assert_eq!(parsed_date("Summer 1990").as_deref(), Some("1990"));
        assert_eq!(parsed_date("circa 1990").as_deref(), Some("1990"));
        assert_eq!(parsed_date("no year here"), None);
        assert_eq!(parsed_date(""), None);
    }

    fn book(key: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut data = json!({
            "key": key, "version": 18, "itemType": "book", "title": "Private research",
            "creators": [{"creatorType": "author", "firstName": "Ada", "lastName": "Lovelace"}],
            "date": "1843",
        });
        data.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        data
    }

    #[test]
    fn regular_item_envelope() {
        let data = book("BQQK2222", json!({}));
        let children = Children {
            notes: 0,
            attachments: 1,
            annotations: 0,
        };
        let value = item(
            &alice(),
            "B",
            18,
            data.clone(),
            children,
            true,
            Some("author"),
        );
        assert_eq!(
            value,
            json!({
                "key": "BQQK2222",
                "version": 18,
                "library": {"type": "user", "id": 101, "name": "Alice"},
                "links": {"self": {"href": "B/users/101/items/BQQK2222", "type": "application/json"}},
                "meta": {"creatorSummary": "Lovelace", "parsedDate": "1843", "numChildren": 1},
                "data": data,
            })
        );
        let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["key", "version", "library", "links", "meta", "data"]);
    }

    #[test]
    fn regular_item_hides_notes_without_note_access() {
        let children = Children {
            notes: 2,
            attachments: 1,
            annotations: 0,
        };
        let value = item(
            &alice(),
            "B",
            18,
            book("BQQK2222", json!({})),
            children,
            false,
            Some("author"),
        );
        assert_eq!(value["meta"]["numChildren"], 1);
        let value = item(
            &alice(),
            "B",
            18,
            book("BQQK2222", json!({})),
            children,
            true,
            Some("author"),
        );
        assert_eq!(value["meta"]["numChildren"], 3);
    }

    #[test]
    fn child_item_envelope() {
        let data = json!({
            "key": "LINK2222", "version": 17, "itemType": "attachment",
            "linkMode": "linked_url", "parentItem": "BQQK2222", "contentType": "",
        });
        let value = item(&alice(), "B", 17, data, Children::default(), true, None);
        assert_eq!(
            value["links"],
            json!({
                "self": {"href": "B/users/101/items/LINK2222", "type": "application/json"},
                "up": {"href": "B/users/101/items/BQQK2222", "type": "application/json"},
            })
        );
        assert_eq!(value["meta"], json!({}));
    }

    #[test]
    fn notes_and_pdfs_count_their_children() {
        let note = json!({"key": "NOTE2222", "itemType": "note", "note": ""});
        let children = Children {
            notes: 0,
            attachments: 2,
            annotations: 0,
        };
        assert_eq!(
            item(&alice(), "B", 1, note, children, true, None)["meta"],
            json!({"numChildren": 2})
        );

        let pdf =
            json!({"key": "PDFA2222", "itemType": "attachment", "contentType": "application/pdf"});
        let children = Children {
            notes: 0,
            attachments: 0,
            annotations: 4,
        };
        assert_eq!(
            item(&alice(), "B", 1, pdf.clone(), children, true, None)["meta"],
            json!({"numChildren": 4})
        );
        // Annotations depend on note access.
        assert_eq!(
            item(&alice(), "B", 1, pdf, children, false, None)["meta"],
            json!({})
        );
    }
}
