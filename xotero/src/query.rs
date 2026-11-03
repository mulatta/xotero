//! Parsing for the item, collection and search listing APIs.
//!
//! This module is pure — it turns the request's query string into a
//! [`Listing`] or [`ItemQuery`] without touching the database — so the filter/sort/paginate
//! semantics can be unit-tested. `store::query_items` turns the result into SQL.

/// Multi-valued query parameters. axum's `Query<HashMap>` collapses repeated
/// keys, but Zotero's `tag` filter repeats the key to mean AND, so we keep every
/// occurrence and decode percent-escapes once.
pub struct Params(Vec<(String, String)>);

impl Params {
    pub fn parse(raw: Option<&str>) -> Self {
        let pairs = raw
            .and_then(|q| serde_urlencoded::from_str::<Vec<(String, String)>>(q).ok())
            .unwrap_or_default();
        Params(pairs)
    }

    /// First value for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every value given for `key`, in order.
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// `itemType` filter: a value like `book || journalArticle` includes those
/// types; a `-` prefix (`-attachment`) excludes one. An item matches when its
/// type is in `include` (or `include` is empty) and not in `exclude`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TypeFilter {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl TypeFilter {
    fn parse(value: Option<&str>) -> Self {
        let mut filter = TypeFilter::default();
        let Some(value) = value else {
            return filter;
        };
        for token in value.split("||").map(str::trim).filter(|t| !t.is_empty()) {
            if let Some(neg) = token.strip_prefix('-') {
                filter.exclude.push(neg.trim().to_string());
            } else {
                filter.include.push(token.to_string());
            }
        }
        filter
    }
}

/// What `q` matches. `titleCreatorYear` (the default) searches title, creators
/// and date; `everything` additionally searches stored full-text content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QMode {
    TitleCreatorYear,
    Everything,
}

impl QMode {
    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("everything") => QMode::Everything,
            _ => QMode::TitleCreatorYear,
        }
    }
}

/// A listing request the server cannot answer. Upstream rejects these with a
/// specific message; xotero answers every one with the same 400.
#[derive(Debug, PartialEq, Eq)]
pub struct Unsupported;

/// Response format of a listing. atom, bib and the export formats are not
/// served, so they parse to `Unsupported` rather than falling back to JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Keys,
    Versions,
}

impl Format {
    fn parse(value: Option<&str>) -> Result<Self, Unsupported> {
        match value {
            None | Some("json") => Ok(Format::Json),
            Some("keys") => Ok(Format::Keys),
            Some("versions") => Ok(Format::Versions),
            Some(_) => Err(Unsupported),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Keys => "keys",
            Format::Versions => "versions",
        }
    }

    /// Upstream page size: json pages by 25 (max 100); keys and versions are
    /// unlimited unless the request names a limit.
    fn default_limit(self) -> i64 {
        match self {
            Format::Json => 25,
            Format::Keys | Format::Versions => 0,
        }
    }

    fn max_limit(self) -> Option<i64> {
        match self {
            Format::Json => Some(100),
            Format::Keys | Format::Versions => None,
        }
    }
}

/// Which object listing is requested; it decides the accepted sorts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Items,
    Collections,
    Searches,
}

/// Sort key, named after its upstream `sort` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    DateModified,
    DateAdded,
    Title,
    Creator,
    Date,
    ItemType,
    Publisher,
    PublicationTitle,
    JournalAbbreviation,
    Language,
    AccessDate,
    LibraryCatalog,
    CallNumber,
    Rights,
    Extra,
    AddedBy,
    ServerDateModified,
}

impl Sort {
    const ALL: [(&'static str, Sort); 17] = [
        ("dateModified", Sort::DateModified),
        ("dateAdded", Sort::DateAdded),
        ("title", Sort::Title),
        ("creator", Sort::Creator),
        ("date", Sort::Date),
        ("itemType", Sort::ItemType),
        ("publisher", Sort::Publisher),
        ("publicationTitle", Sort::PublicationTitle),
        ("journalAbbreviation", Sort::JournalAbbreviation),
        ("language", Sort::Language),
        ("accessDate", Sort::AccessDate),
        ("libraryCatalog", Sort::LibraryCatalog),
        ("callNumber", Sort::CallNumber),
        ("rights", Sort::Rights),
        ("extra", Sort::Extra),
        ("addedBy", Sort::AddedBy),
        ("serverDateModified", Sort::ServerDateModified),
    ];

    fn parse(value: &str, kind: ListKind) -> Result<Self, Unsupported> {
        let sort = Sort::ALL
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, sort)| *sort)
            .ok_or(Unsupported)?;
        match kind {
            ListKind::Items => Ok(sort),
            ListKind::Collections | ListKind::Searches => match sort {
                Sort::Title | Sort::DateAdded | Sort::DateModified => Ok(sort),
                _ => Err(Unsupported),
            },
        }
    }

    pub fn name(self) -> &'static str {
        Sort::ALL
            .iter()
            .find(|(_, sort)| *sort == self)
            .map(|(name, _)| *name)
            .expect("every sort is named")
    }

    /// Upstream `getDefaultDirection`: date fields newest first.
    pub fn default_direction(self) -> Direction {
        if self.name().starts_with("date") {
            Direction::Desc
        } else {
            Direction::Asc
        }
    }

    /// Upstream `getSortEmptyFirst`: these sorts order empty values as lowest
    /// instead of pushing them behind the non-empty ones.
    pub fn empty_first(self) -> bool {
        matches!(self, Sort::Title | Sort::Date)
    }

    /// The SQL expression to order collections and searches by. Their JSON has
    /// no timestamps, so the date sorts fall back to version order (`None`).
    pub fn named_order_expr(self) -> Option<&'static str> {
        match self {
            Sort::Title => Some("data->>'name'"),
            _ => None,
        }
    }

    /// The SQL expression to order items by. `date`/`itemType` use the generated
    /// columns (migration 0006) — `date_year` is the first 4-digit year from the
    /// freeform date, so "circa 1990" / "January 2000" sort chronologically
    /// rather than by their leading character. `creator` orders by the first
    /// creator's last name; the rest read a top-level jsonb field. xotero
    /// records no adding user, so `addedBy` orders by `dateAdded`, and keeps
    /// no separate server timestamp, so `serverDateModified` by `dateModified`.
    pub fn order_expr(self) -> &'static str {
        match self {
            Sort::DateModified | Sort::ServerDateModified => "data->>'dateModified'",
            Sort::DateAdded | Sort::AddedBy => "data->>'dateAdded'",
            Sort::Title => "data->>'title'",
            Sort::Creator => "data->'creators'->0->>'lastName'",
            Sort::Date => "date_year",
            Sort::ItemType => "item_type",
            Sort::Publisher => "data->>'publisher'",
            Sort::PublicationTitle => "data->>'publicationTitle'",
            Sort::JournalAbbreviation => "data->>'journalAbbreviation'",
            Sort::Language => "data->>'language'",
            Sort::AccessDate => "data->>'accessDate'",
            Sort::LibraryCatalog => "data->>'libraryCatalog'",
            Sort::CallNumber => "data->>'callNumber'",
            Sort::Rights => "data->>'rights'",
            Sort::Extra => "data->>'extra'",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Asc,
    Desc,
}

impl Direction {
    fn parse(value: &str) -> Result<Self, Unsupported> {
        match value {
            "asc" => Ok(Direction::Asc),
            "desc" => Ok(Direction::Desc),
            _ => Err(Unsupported),
        }
    }

    pub fn sql(self) -> &'static str {
        match self {
            Direction::Asc => "asc",
            Direction::Desc => "desc",
        }
    }
}

/// The paging and rendering half of a listing request, shared by items,
/// collections and searches.
#[derive(Debug)]
pub struct Listing {
    pub format: Format,
    pub sort: Sort,
    pub direction: Direction,
    /// Page size; 0 means unlimited.
    pub limit: i64,
    pub start: i64,
    pub since: Option<i64>,
}

impl Listing {
    pub fn parse(params: &Params, kind: ListKind) -> Result<Self, Unsupported> {
        let format = Format::parse(params.get("format"))?;

        // Upstream moves `sort=asc|desc` to the direction of the default sort.
        let (sort, sort_direction) = match params.get("sort") {
            None => (Sort::DateModified, None),
            Some(value @ ("asc" | "desc")) => (Sort::DateModified, Some(Direction::parse(value)?)),
            Some(value) => (Sort::parse(value, kind)?, None),
        };
        let direction = match (sort_direction, params.get("direction")) {
            (Some(direction), _) => direction,
            (None, Some(value)) => Direction::parse(value)?,
            (None, None) => sort.default_direction(),
        };

        // Like upstream, a non-positive or unparseable limit keeps the default.
        let limit = match params.get("limit").and_then(|s| s.parse::<i64>().ok()) {
            Some(n) if n > 0 => format.max_limit().map_or(n, |max| n.min(max)),
            _ => format.default_limit(),
        };
        let start = params
            .get("start")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|n| *n >= 0)
            .unwrap_or(0);
        let since = params
            .get("since")
            .map(|s| s.parse::<i64>().map_err(|_| Unsupported))
            .transpose()?;

        Ok(Listing {
            format,
            sort,
            direction,
            limit,
            start,
            since,
        })
    }

    /// Upstream `getNonDefaultParams` without `start`: the query parameters a
    /// `Link` URL must repeat, sorted by name. Parameters upstream does not know
    /// (such as `key`) are dropped.
    pub fn link_params(&self, params: &Params) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        if self.format != Format::Json {
            out.push(("format".into(), self.format.name().into()));
        }
        if self.sort != Sort::DateModified {
            out.push(("sort".into(), self.sort.name().into()));
        }
        if self.direction != self.sort.default_direction() {
            out.push(("direction".into(), self.direction.sql().into()));
        }
        if self.limit != self.format.default_limit() {
            out.push(("limit".into(), self.limit.to_string()));
        }
        if let Some(since) = self.since {
            out.push(("since".into(), since.to_string()));
        }
        for (name, default) in FILTER_DEFAULTS {
            let values = params.all(name);
            if values.is_empty() {
                continue;
            }
            // PHP turns a repeated parameter into an array and joins it with ','.
            let value = values.join(",");
            if value != default {
                out.push((name.into(), value));
            }
        }
        out.sort();
        out
    }

    /// The `order by` list for a listing sorted by `expr`: upstream's
    /// empty-value rule, then version and key in the same direction. Without
    /// `expr` the listing orders by version and key alone.
    pub fn order_by(&self, expr: Option<&str>) -> String {
        let dir = self.direction.sql();
        let Some(expr) = expr else {
            return format!("version {dir}, key {dir}");
        };
        let sort = if self.sort.empty_first() {
            let nulls = match self.direction {
                Direction::Asc => "first",
                Direction::Desc => "last",
            };
            format!("nullif({expr}, '') {dir} nulls {nulls}")
        } else {
            format!("coalesce({expr}, '') = '' {dir}, {expr} {dir}")
        };
        format!("{sort}, version {dir}, key {dir}")
    }
}

/// Upstream filter parameters and their defaults, as `getNonDefaultParams`
/// compares them. `includeTrashed` defaults to 0, which PHP equates with "0".
const FILTER_DEFAULTS: [(&str, &str); 10] = [
    ("collectionKey", ""),
    ("include", "data"),
    ("includeTrashed", "0"),
    ("itemKey", ""),
    ("itemType", ""),
    ("q", ""),
    ("qmode", ""),
    ("searchKey", ""),
    ("tag", ""),
    ("tagType", ""),
];

/// A parsed item listing request: a search term, filters and the shared
/// listing window. Built from the query string; consumed by `store::query_items`.
#[derive(Debug)]
pub struct ItemQuery {
    pub q: Option<String>,
    pub qmode: QMode,
    pub item_type: TypeFilter,
    /// AND of OR-groups: each repeated `tag` param is one group, `||`-split into
    /// alternatives. An item must carry a tag from every group.
    pub tags: Vec<Vec<String>>,
    pub listing: Listing,
    pub include_trashed: bool,
    /// Convenience-route filters, set by the handler rather than parsed from the
    /// query string: `top` keeps only top-level items (no `parentItem`),
    /// `only_trashed` inverts the trash filter to return just trashed items, and
    /// `collection` keeps items whose `data.collections` contains that key.
    pub top: bool,
    pub only_trashed: bool,
    pub collection: Option<String>,
}

impl ItemQuery {
    pub fn from_params(params: &Params) -> Result<Self, Unsupported> {
        let q = params
            .get("q")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);

        let tags = params
            .all("tag")
            .into_iter()
            .map(|group| {
                group
                    .split("||")
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .filter(|group: &Vec<String>| !group.is_empty())
            .collect();

        let include_trashed = matches!(params.get("includeTrashed"), Some("1") | Some("true"));

        Ok(ItemQuery {
            q,
            qmode: QMode::parse(params.get("qmode")),
            item_type: TypeFilter::parse(params.get("itemType")),
            tags,
            listing: Listing::parse(params, ListKind::Items)?,
            include_trashed,
            top: false,
            only_trashed: false,
            collection: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(raw: &str) -> ItemQuery {
        ItemQuery::from_params(&Params::parse(Some(raw))).unwrap()
    }

    #[test]
    fn defaults_when_empty() {
        let q = query("");
        assert!(q.q.is_none());
        assert_eq!(q.qmode, QMode::TitleCreatorYear);
        assert_eq!(q.listing.sort, Sort::DateModified);
        assert_eq!(q.listing.direction, Direction::Desc);
        assert_eq!(q.listing.limit, 25);
        assert_eq!(q.listing.start, 0);
        assert!(!q.include_trashed);
        assert!(q.tags.is_empty());
        assert_eq!(q.item_type, TypeFilter::default());
        // Convenience-route filters are off until a handler sets them.
        assert!(!q.top);
        assert!(!q.only_trashed);
        assert!(q.collection.is_none());
    }

    #[test]
    fn blank_q_is_dropped() {
        assert!(query("q=").q.is_none());
        assert!(query("q=%20%20").q.is_none());
        assert_eq!(query("q=rust").q.as_deref(), Some("rust"));
    }

    #[test]
    fn qmode_everything_opt_in() {
        assert_eq!(query("qmode=everything").qmode, QMode::Everything);
        assert_eq!(
            query("qmode=titleCreatorYear").qmode,
            QMode::TitleCreatorYear
        );
        assert_eq!(query("qmode=bogus").qmode, QMode::TitleCreatorYear);
    }

    #[test]
    fn item_type_includes_and_excludes() {
        let f = query("itemType=book || journalArticle").item_type;
        assert_eq!(f.include, vec!["book", "journalArticle"]);
        assert!(f.exclude.is_empty());

        let f = query("itemType=-note || -attachment").item_type;
        assert!(f.include.is_empty());
        assert_eq!(f.exclude, vec!["note", "attachment"]);

        let f = query("itemType=book || -note").item_type;
        assert_eq!(f.include, vec!["book"]);
        assert_eq!(f.exclude, vec!["note"]);
    }

    #[test]
    fn tags_repeat_for_and_pipe_for_or() {
        // Two repeated params -> two AND groups; the second has two OR alternatives.
        let q = query("tag=urgent&tag=todo || later");
        assert_eq!(q.tags, vec![vec!["urgent"], vec!["todo", "later"]]);
    }

    #[test]
    fn limit_is_clamped_and_start_floored() {
        assert_eq!(query("limit=500").listing.limit, 100);
        assert_eq!(query("limit=0").listing.limit, 25);
        assert_eq!(query("limit=-3").listing.limit, 25);
        assert_eq!(query("limit=10").listing.limit, 10);
        assert_eq!(query("start=-5").listing.start, 0);
        assert_eq!(query("start=40").listing.start, 40);
    }

    #[test]
    fn include_trashed_opt_in() {
        assert!(query("includeTrashed=1").include_trashed);
        assert!(query("includeTrashed=true").include_trashed);
        assert!(!query("includeTrashed=0").include_trashed);
        assert!(!query("").include_trashed);
    }

    #[test]
    fn sort_and_direction_whitelist() {
        assert_eq!(query("sort=title").listing.sort, Sort::Title);
        assert_eq!(query("sort=creator").listing.sort, Sort::Creator);
        assert_eq!(query("direction=asc").listing.direction, Direction::Asc);
        assert_eq!(
            Sort::Creator.order_expr(),
            "data->'creators'->0->>'lastName'"
        );
        // date/itemType sort via the generated columns (migration 0006).
        assert_eq!(query("sort=date").listing.sort, Sort::Date);
        assert_eq!(Sort::Date.order_expr(), "date_year");
        assert_eq!(Sort::ItemType.order_expr(), "item_type");
    }

    fn listing(raw: &str, kind: ListKind) -> Result<Listing, Unsupported> {
        Listing::parse(&Params::parse(Some(raw)), kind)
    }

    #[test]
    fn listing_rejects_unsupported_requests() {
        for raw in [
            "format=bogus",
            "format=atom",
            "format=bib",
            "format=ris",
            "sort=bogus",
            "sort=numItems",
            "sort=itemKeyList",
            "direction=sideways",
            "since=abc",
        ] {
            assert!(listing(raw, ListKind::Items).is_err(), "{raw}");
        }
        assert!(listing("sort=creator", ListKind::Collections).is_err());
        assert!(listing("sort=publisher", ListKind::Searches).is_err());
    }

    #[test]
    fn listing_defaults_follow_upstream() {
        let l = listing("", ListKind::Items).unwrap();
        assert_eq!(l.format, Format::Json);
        assert_eq!(l.sort, Sort::DateModified);
        assert_eq!(l.direction, Direction::Desc);
        assert_eq!((l.limit, l.start, l.since), (25, 0, None));
        assert_eq!(listing("format=keys", ListKind::Items).unwrap().limit, 0);
        assert_eq!(
            listing("format=versions", ListKind::Items).unwrap().limit,
            0
        );
        assert_eq!(
            listing("format=keys&limit=500", ListKind::Items)
                .unwrap()
                .limit,
            500
        );
        assert_eq!(listing("limit=500", ListKind::Items).unwrap().limit, 100);
        assert_eq!(listing("limit=0", ListKind::Items).unwrap().limit, 25);
        assert_eq!(
            listing("since=17", ListKind::Items).unwrap().since,
            Some(17)
        );
    }

    #[test]
    fn direction_defaults_by_sort() {
        let dir = |raw| listing(raw, ListKind::Items).unwrap().direction;
        assert_eq!(dir("sort=title"), Direction::Asc);
        assert_eq!(dir("sort=publisher"), Direction::Asc);
        assert_eq!(dir("sort=addedBy"), Direction::Asc);
        assert_eq!(dir("sort=date"), Direction::Desc);
        assert_eq!(dir("sort=dateAdded"), Direction::Desc);
        assert_eq!(dir("sort=title&direction=desc"), Direction::Desc);
        // sort=asc|desc is a direction on the default sort.
        let l = listing("sort=asc", ListKind::Items).unwrap();
        assert_eq!((l.sort, l.direction), (Sort::DateModified, Direction::Asc));
    }

    #[test]
    fn collections_and_searches_accept_their_sorts() {
        for kind in [ListKind::Collections, ListKind::Searches] {
            for raw in [
                "sort=title",
                "sort=dateAdded",
                "sort=dateModified",
                "format=keys",
                "format=versions",
            ] {
                assert!(listing(raw, kind).is_ok(), "{raw}");
            }
        }
    }

    fn link_params(raw: &str) -> Vec<(String, String)> {
        let params = Params::parse(Some(raw));
        Listing::parse(&params, ListKind::Items)
            .unwrap()
            .link_params(&params)
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn link_params_keep_only_non_defaults_sorted() {
        assert!(link_params("").is_empty());
        assert!(
            link_params("format=json&sort=dateModified&direction=desc&limit=25&start=5").is_empty()
        );
        assert_eq!(
            link_params("sort=title&key=secret"),
            pairs(&[("sort", "title")])
        );
        // date's default direction is desc, so only the sort survives.
        assert_eq!(
            link_params("sort=date&direction=desc"),
            pairs(&[("sort", "date")])
        );
        assert_eq!(
            link_params("sort=title&direction=desc"),
            pairs(&[("direction", "desc"), ("sort", "title")])
        );
        assert_eq!(
            link_params("sort=title&limit=25&format=keys"),
            pairs(&[("format", "keys"), ("limit", "25"), ("sort", "title")])
        );
        assert_eq!(
            link_params("since=17&q=rust&includeTrashed=0&tag=a&tag=b&itemType=book&include=data"),
            pairs(&[
                ("itemType", "book"),
                ("q", "rust"),
                ("since", "17"),
                ("tag", "a,b")
            ])
        );
        assert_eq!(link_params("sort=asc"), pairs(&[("direction", "asc")]));
    }

    #[test]
    fn server_date_modified_sorts_by_date_modified() {
        let l = listing("sort=serverDateModified", ListKind::Items).unwrap();
        assert_eq!(l.sort.order_expr(), "data->>'dateModified'");
        assert_eq!(l.direction, Direction::Asc);
    }

    #[test]
    fn order_by_ties_break_on_version_then_key() {
        let order = |raw| {
            let l = listing(raw, ListKind::Items).unwrap();
            l.order_by(Some(l.sort.order_expr()))
        };
        // Empty-first sorts: empties are the lowest values.
        assert_eq!(
            order("sort=title"),
            "nullif(data->>'title', '') asc nulls first, version asc, key asc"
        );
        assert_eq!(
            order("sort=date"),
            "nullif(date_year, '') desc nulls last, version desc, key desc"
        );
        // Other sorts put empties after values ascending, before them descending.
        assert_eq!(
            order("sort=creator"),
            "coalesce(data->'creators'->0->>'lastName', '') = '' asc, \
             data->'creators'->0->>'lastName' asc, version asc, key asc"
        );
        assert_eq!(
            order(""),
            "coalesce(data->>'dateModified', '') = '' desc, data->>'dateModified' desc, \
             version desc, key desc"
        );
    }

    #[test]
    fn collections_and_searches_order_by_name_or_version() {
        let order = |raw, kind| {
            let l = listing(raw, kind).unwrap();
            l.order_by(l.sort.named_order_expr())
        };
        for kind in [ListKind::Collections, ListKind::Searches] {
            assert_eq!(
                order("sort=title", kind),
                "nullif(data->>'name', '') asc nulls first, version asc, key asc"
            );
            // Collection and search JSON has no timestamps.
            assert_eq!(order("", kind), "version desc, key desc");
            assert_eq!(
                order("sort=dateAdded&direction=asc", kind),
                "version asc, key asc"
            );
        }
    }
}
