"""Validate fixture wire shapes against their selected contract."""

import re
from typing import assert_never

from models import Contract, Fixture
from wire import OBJECT_KEY, ContractError, require, validate_wire


def validate_fixture(contract: Contract, fixture: Fixture) -> None:
    """Reject method, authority, condition, representation and envelope drift."""
    identity = contract.id
    request, response = fixture.request, fixture.response
    validate_wire(contract, fixture)
    path = contract.path
    for name, value in {
        "{userId}": "101",
        "{groupId}": "303",
        "{key}": "BQQK2222",
        "{collectionKey}": "CQLL2222",
        "{settingKey}": "tagColors",
        "{id}": "202",
        "{keyId}": "71",
        "{uploadKey}": "a" * 32,
        "{token}": "0123456789abcdef0123456789abcdef",
    }.items():
        path = path.replace(name, value)
    require(fixture.scope == contract.scope, f"{identity}: scope mismatch")
    require(request.path == path, f"{identity}: path/library mismatch")
    require(request.method == contract.method, f"{identity}: method mismatch")
    require(
        request.authorization == contract.authorization,
        f"{identity}: authorization mismatch",
    )
    require(request.format == contract.format, f"{identity}: format mismatch")
    require(request.query == contract.query, f"{identity}: query mismatch")
    require(response.status == contract.status, f"{identity}: status mismatch")
    require(
        response.headers == contract.headers, f"{identity}: response headers mismatch"
    )
    condition = contract.precondition
    if condition.required and condition.header:
        require(
            condition.header in request.headers, f"{identity}: missing precondition"
        )
    body = request.body
    valid_body = {
        "none": body is None,
        "object": isinstance(body, dict) and bool(body),
        "array": isinstance(body, list) and bool(body),
        "form": isinstance(body, str) and "=" in body,
        "bytes": isinstance(body, str) and bool(body),
    }[contract.body]
    require(valid_body, f"{identity}: request body shape")
    payload = response.body
    single_object = re.fullmatch(
        rf"/(?:users|groups)/[^/]+/(?:items|collections|searches)/({OBJECT_KEY.pattern})",
        request.path,
    )
    if single_object and response.status < 400:
        key = single_object.group(1)
        if isinstance(body, dict) and "key" in body:
            require(body["key"] == key, f"{identity}: request object identity")
        if request.method == "GET":
            if not isinstance(payload, dict):
                raise ContractError(f"{identity}: single object wrapper")
            data = payload.get("data")
            if not isinstance(data, dict):
                raise ContractError(f"{identity}: single object data")
            require(
                payload.get("key") == key == data.get("key"),
                f"{identity}: response object identity",
            )
            require(
                payload.get("version") == data.get("version"),
                f"{identity}: response data version",
            )
            require(
                str(payload.get("version"))
                == response.headers.get("Last-Modified-Version"),
                f"{identity}: object version header",
            )
    if contract.envelope == "setting":
        if not isinstance(payload, dict):
            raise ContractError(f"{identity}: setting object")
        require(
            str(payload.get("version"))
            == response.headers.get("Last-Modified-Version"),
            f"{identity}: setting version header",
        )
    match contract.envelope:
        case "empty":
            require(payload is None, f"{identity}: empty response body")
        case "list":
            if not isinstance(payload, list):
                raise ContractError(f"{identity}: list envelope")
            require(bool(payload), f"{identity}: empty list fixture")
            for entry in payload:
                require(
                    isinstance(entry, dict)
                    and {"key", "version", "data", "links", "meta"} <= entry.keys(),
                    f"{identity}: incomplete object wrapper",
                )
        case "write-report":
            require(
                isinstance(payload, dict)
                and {"successful", "success", "unchanged", "failed"} <= payload.keys(),
                f"{identity}: write report",
            )
        case "keys" | "url" | "text":
            require(
                isinstance(payload, str) and bool(payload),
                f"{identity}: plain text response",
            )
        case "export":
            require(
                isinstance(payload, str) and bool(payload),
                f"{identity}: serialized export",
            )
        case "setting":
            require(
                isinstance(payload, dict) and {"value", "version"} <= payload.keys(),
                f"{identity}: setting envelope",
            )
        case "tags":
            if not isinstance(payload, list):
                raise ContractError(f"{identity}: tags envelope")
            require(bool(payload), f"{identity}: empty tag fixture")
            for tag in payload:
                require(
                    isinstance(tag, dict) and {"tag", "meta"} <= tag.keys(),
                    f"{identity}: tag wrapper",
                )
        case "metadata":
            if not isinstance(payload, list):
                raise ContractError(f"{identity}: localized metadata array")
            require(bool(payload), f"{identity}: empty metadata fixture")
            for entry in payload:
                require(
                    isinstance(entry, dict) and "localized" in entry,
                    f"{identity}: localized metadata entry",
                )
        case "groups":
            if not isinstance(payload, list):
                raise ContractError(f"{identity}: group listing array")
            require(bool(payload), f"{identity}: empty group fixture")
            for entry in payload:
                require(
                    isinstance(entry, dict)
                    and {"id", "version", "links", "meta", "data"} <= entry.keys(),
                    f"{identity}: group wrapper",
                )
        case "deleted":
            if not isinstance(payload, dict):
                raise ContractError(f"{identity}: deleted envelope")
            tags = payload.get("tags")
            if not isinstance(tags, list):
                raise ContractError(f"{identity}: deleted tags array")
            require(
                all(isinstance(tag, str) for tag in tags), f"{identity}: deleted tags"
            )
        case "redirect":
            require(
                payload is None and "Location" in response.headers,
                f"{identity}: file redirect",
            )
        case (
            "versions"
            | "settings"
            | "template"
            | "object"
            | "fulltext-status"
            | "schema"
            | "form-result"
            | "error"
        ):
            require(
                isinstance(payload, dict) and bool(payload),
                f"{identity}: object response",
            )
        case unreachable:
            assert_never(unreachable)
