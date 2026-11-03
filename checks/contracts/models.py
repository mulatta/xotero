"""Strict machine boundary for target contracts, not claims of server support."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

Text = Annotated[str, Field(min_length=1)]
Method = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
Scope = Literal["personal", "private-group", "global"]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Source(Record):
    repository: Text
    revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    version: Text
    lock_sha256: str | None
    gitlinks: dict[str, str]
    integrity: dict[str, str]
    consumers: dict[str, str]


class Citation(Record):
    source: Text
    path: Text
    lines: Text


class Authorization(Record):
    kind: Literal[
        "key-or-gateway",
        "session",
        "instance-admin",
        "public",
        "upload-token",
        "signed-url",
    ]
    permission: Text
    denial: Annotated[int, Field(ge=400, le=499)]


class Precondition(Record):
    scope: Literal["none", "library", "object", "setting", "group", "file", "csrf"]
    header: str | None
    required: bool
    alternative: str | None


class Proof(Record):
    state: Literal["covered", "partial", "pending", "unsupported"]
    task: Annotated[int, Field(ge=1, le=40)]
    file: str | None
    subtest: Text
    reason: Text


class Contract(Record):
    id: Text
    origin: Literal[
        "observed-web", "client-supported", "fixed-scope", "intentionally-unsupported"
    ]
    method: Method
    path: Annotated[str, Field(pattern=r"^/")]
    scope: Scope
    query: dict[str, JsonValue]
    body: Literal["none", "object", "array", "form", "bytes"]
    envelope: Literal[
        "list",
        "object",
        "write-report",
        "keys",
        "versions",
        "setting",
        "settings",
        "tags",
        "deleted",
        "template",
        "redirect",
        "url",
        "empty",
        "export",
        "fulltext-status",
        "schema",
        "error",
        "form-result",
        "text",
        "metadata",
        "groups",
    ]
    precondition: Precondition
    authorization: Authorization
    status: Annotated[int, Field(ge=200, le=599)]
    headers: dict[str, str]
    format: Text
    sources: Annotated[list[Citation], Field(min_length=1)]
    proof: Proof


class ExportFormat(Record):
    key: Text
    extension: str | None
    mime: Text
    translator: Annotated[str, Field(pattern=r"^[0-9a-f-]{36}$")]


class Discrepancy(Record):
    id: Text
    tasks: list[int]
    correction: Text
    sources: Annotated[list[Citation], Field(min_length=1)]


class Inventory(Record):
    schema_version: Literal[1]
    purpose: Literal["target-contract-inventory"]
    base: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    sources: dict[str, Source]
    formats: list[ExportFormat]
    assets: dict[str, str]
    requirements: dict[str, JsonValue]
    discrepancies: list[Discrepancy]
    contracts: Annotated[list[Contract], Field(min_length=1)]


class Request(Record):
    method: Method
    path: Text
    authorization: Authorization
    format: Text
    query: dict[str, JsonValue]
    headers: dict[str, str]
    body: JsonValue


class Response(Record):
    status: Annotated[int, Field(ge=200, le=599)]
    headers: dict[str, str]
    body: JsonValue


class Fixture(Record):
    contract: Text
    scope: Scope
    kind: Literal["expected-contract"]
    request: Request
    response: Response
    sequence: list[str] | None = None
