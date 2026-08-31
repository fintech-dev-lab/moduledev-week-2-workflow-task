#!/usr/bin/env python3
"""Run the published week-2 black-box contract checks."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


MANIFEST_VERSION = "week-2-public-report/v1"
TOOL_VERSION = "week-2-public-check/1.1"
PUBLISHED_FIXTURE_DIGEST = (
    "fdae621f8c88b02e4ee50ba3cec2658470a177da68e5b438349a380d100071d4"
)
PUBLISHED_FIXTURE_GENERATOR = "week-2.1"
COMPOSE_NAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
)
REQUIRED_SERVICES = {
    "gateway",
    "api",
    "cli",
    "postgres",
    "worker-a",
    "worker-b",
}
AUTOCHECK_VIEWS = {
    "flow_versions",
    "processes",
    "steps",
    "jobs",
    "attempts",
    "signals",
    "workflow_events",
    "action_dispatches",
    "action_definitions",
}
AUTOCHECK_VIEW_SCHEMAS = {
    "action_definitions": (
        ("module", "text"),
        ("action", "text"),
        ("version", "integer"),
        ("http_method", "text"),
        ("target_schema", "text"),
        ("target_function", "text"),
        ("outcomes", "jsonb"),
        ("enabled", "boolean"),
        ("is_default", "boolean"),
    ),
    "action_dispatches": (
        ("correlation_id", "uuid"),
        ("request_id", "text"),
        ("module", "text"),
        ("action", "text"),
        ("version", "integer"),
        ("principal", "text"),
        ("payload_hash", "text"),
        ("status", "text"),
        ("outcome", "text"),
        ("occurred_at", "timestamp with time zone"),
    ),
    "flow_versions": (
        ("flow_name", "text"),
        ("flow_version", "integer"),
        ("status", "text"),
        ("is_active", "boolean"),
        ("published_at", "timestamp with time zone"),
    ),
    "processes": (
        ("process_id", "uuid"),
        ("business_key", "text"),
        ("flow_name", "text"),
        ("flow_version", "integer"),
        ("state", "text"),
        ("current_step_key", "text"),
        ("created_at", "timestamp with time zone"),
        ("updated_at", "timestamp with time zone"),
    ),
    "steps": (
        ("step_instance_id", "uuid"),
        ("process_id", "uuid"),
        ("step_key", "text"),
        ("step_type", "text"),
        ("state", "text"),
        ("outcome", "text"),
        ("entered_at", "timestamp with time zone"),
        ("completed_at", "timestamp with time zone"),
    ),
    "jobs": (
        ("job_id", "uuid"),
        ("process_id", "uuid"),
        ("step_instance_id", "uuid"),
        ("execution_id", "uuid"),
        ("state", "text"),
        ("lease_owner", "text"),
        ("lease_version", "bigint"),
        ("lease_until", "timestamp with time zone"),
        ("attempt_count", "integer"),
        ("next_attempt_at", "timestamp with time zone"),
    ),
    "attempts": (
        ("attempt_id", "uuid"),
        ("job_id", "uuid"),
        ("execution_id", "uuid"),
        ("lease_version", "bigint"),
        ("attempt_number", "integer"),
        ("status", "text"),
        ("outcome", "text"),
        ("error_code", "text"),
        ("started_at", "timestamp with time zone"),
        ("finished_at", "timestamp with time zone"),
    ),
    "signals": (
        ("message_id", "text"),
        ("process_id", "uuid"),
        ("signal_type", "text"),
        ("body_hash", "text"),
        ("status", "text"),
        ("received_at", "timestamp with time zone"),
    ),
    "workflow_events": (
        ("event_id", "uuid"),
        ("process_id", "uuid"),
        ("step_instance_id", "uuid"),
        ("event_type", "text"),
        ("occurred_at", "timestamp with time zone"),
    ),
}
FIXTURE_FIELDS = {
    "action",
    "actionVersion",
    "businessKeys",
    "businessValues",
    "contractVersion",
    "digest",
    "effectTable",
    "errorCodes",
    "files",
    "flowName",
    "generationPhase",
    "generatorVersion",
    "modes",
    "module",
    "orderingOwner",
    "outcomes",
    "processProperties",
    "properties",
    "seedMode",
    "signalMessageId",
    "signalType",
    "steps",
    "targetFunction",
    "targetSchema",
}
FIXTURE_OBJECT_FIELDS = {
    "businessKeys": {"signal", "manual", "retry", "error", "unknown", "invalid", "v2"},
    "businessValues": {
        "signal",
        "manual",
        "retry",
        "error",
        "unknown",
        "invalid",
        "changed",
        "marker",
        "signalPayload",
        "result",
    },
    "errorCodes": {"retry", "error"},
    "modes": {"signal", "manual", "retry", "error", "unknown", "invalid"},
    "outcomes": {
        "signal",
        "manual",
        "received",
        "approved",
        "completed",
        "unknown",
        "abandoned",
    },
    "processProperties": {"mode", "value"},
    "properties": {
        "mode",
        "value",
        "marker",
        "stored",
        "revision",
        "echo",
        "execution",
    },
    "steps": {"automatic", "wait", "manual", "end"},
}
FIXTURE_FILE_FIELDS = {
    "migration",
    "actionManifest",
    "disabledActionManifest",
    "flowV1Json",
    "flowV2Json",
    "flowV1Yaml",
    "flowV2Yaml",
    "invalidMaps",
    "processData",
    "signalData",
    "resultData",
}
PROCESS_DATA_FIELDS = {
    "signal",
    "manual",
    "retry",
    "error",
    "unknown",
    "invalid",
    "changed",
}
SOLUTION_HEADINGS = {
    "архитектура",
    "запуск",
    "workflow-карты",
    "worker",
    "проверка",
    "диагностика",
    "ограничения",
}
README_LITERALS = (
    "docker compose up -d --build",
    "./check.sh",
)
PHASE_CHECKS = {
    "publication": (
        "migration-and-action-publication",
        "map-validation-and-publication",
        "publication-image-immutability",
    ),
    "execution": (
        "automatic-signal-end",
        "signal-idempotency-and-history",
        "manual-wait",
        "stable-views",
    ),
    "versioning": ("version-pinning-and-start-idempotency",),
    "concurrency": ("two-worker-reclaim-and-stale-finish",),
    "recovery": ("action-finish-rollback-and-recovery",),
    "resilience": (
        "bounded-retry-and-terminal-failures",
        "worker-recreate-persistence",
    ),
    "integrity": ("runtime-image-immutability",),
}
_SECRET_KEY = re.compile(
    r"(?:authorization|password|secret|signing(?:[_-]?key)?|token|payload|processdata|body)$",
    re.IGNORECASE,
)
_TRANSPORT_ERROR = re.compile(
    r"(?:cannot connect to the docker daemon|is the docker daemon running|"
    r"error during connect|context deadline exceeded|connection refused|"
    r"no route to host|server closed the connection|could not connect|"
    r"permission denied.*(?:docker|daemon|sock)|(?:docker|daemon|sock).*permission denied|"
    r"unknown (?:flag|shorthand flag).*no-env-resolution|"
    r"compose.*is not a docker command|unknown docker command.*compose|"
    r"unsupported.*(?:!reset|!override)|unknown tag.*(?:!reset|!override))",
    re.IGNORECASE,
)
_WRITE_WORD = re.compile(
    r"\b(?:insert|update|delete|merge|alter|drop|create|grant|revoke|truncate|"
    r"copy|call|do|vacuum|refresh|reindex|cluster)\b",
    re.IGNORECASE,
)
_SQL_STRING_LITERAL = re.compile(r"'(?:''|[^'])*'")


class FixtureError(ValueError):
    """Trusted fixture metadata or contents are invalid."""


class ContractError(RuntimeError):
    """The candidate surface did not satisfy a published contract."""


class EnvironmentFailure(RuntimeError):
    """The checker could not use its local Docker or process transport."""


@dataclass
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass
class HttpResult:
    status: int
    body: dict[str, Any] | None
    error: str | None = None


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def issue_token(secret: str, subject: str, scopes: Sequence[str]) -> str:
    now = int(time.time())
    header = _base64url(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    payload = _base64url(
        json.dumps(
            {
                "iss": "moduledev-course",
                "aud": "moduledev-api",
                "sub": subject,
                "consumer": "public-check",
                "scope": " ".join(scopes),
                "iat": now,
                "exp": now + 900,
            },
            separators=(",", ":"),
        ).encode()
    )
    signature = hmac.new(
        secret.encode(), f"{header}.{payload}".encode("ascii"), hashlib.sha256
    ).digest()
    return f"{header}.{payload}.{_base64url(signature)}"


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def canonical_fixture_digest(root: Path) -> str:
    """Hash every fixture file and canonicalize fixture.json without its digest."""

    root = root.resolve()
    digest = hashlib.sha256()
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        if relative == "fixture.json":
            try:
                metadata = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise FixtureError(f"Invalid fixture.json: {error}") from error
            if not isinstance(metadata, dict):
                raise FixtureError("fixture.json must contain an object")
            metadata.pop("digest", None)
            contents = (
                json.dumps(
                    metadata,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        else:
            contents = path.read_bytes()
        digest.update(contents)
        digest.update(b"\0")
    return digest.hexdigest()


def _fixture_paths(files: dict[str, Any]) -> set[str]:
    paths = {
        str(files[name])
        for name in FIXTURE_FILE_FIELDS
        if name not in {"invalidMaps", "processData"}
    }
    paths.update(str(path) for path in files["invalidMaps"]["schema"])
    paths.update(str(path) for path in files["invalidMaps"]["semantic"])
    paths.update(str(path) for path in files["processData"].values())
    return paths


def load_fixture(root: Path) -> dict[str, Any]:
    root = root.expanduser().resolve()
    path = root / "fixture.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FixtureError(f"Cannot read fixture.json: {error}") from error
    if not isinstance(value, dict) or set(value) != FIXTURE_FIELDS:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise FixtureError(
            f"fixture.json fields differ from the published fixture: {actual}"
        )
    if value.get("contractVersion") != "course-1":
        raise FixtureError("Fixture contractVersion must be course-1")
    if value.get("generatorVersion") != PUBLISHED_FIXTURE_GENERATOR:
        raise FixtureError("Fixture generatorVersion is not the published version")
    if (
        value.get("generationPhase") != "post-build"
        or value.get("orderingOwner") != "runner"
    ):
        raise FixtureError("Fixture generation/order metadata is invalid")
    if value.get("seedMode") != "explicit-test-seed" or value.get("actionVersion") != 1:
        raise FixtureError("Fixture seed/action metadata is invalid")
    for field, expected in FIXTURE_OBJECT_FIELDS.items():
        child = value.get(field)
        if not isinstance(child, dict) or set(child) != expected:
            raise FixtureError(f"Fixture object {field} has invalid fields")
        if any(not isinstance(item, str) or not item for item in child.values()):
            raise FixtureError(f"Fixture object {field} must contain non-empty strings")
    files = value.get("files")
    if not isinstance(files, dict) or set(files) != FIXTURE_FILE_FIELDS:
        raise FixtureError("Fixture files object has invalid fields")
    invalid = files.get("invalidMaps")
    if not isinstance(invalid, dict) or set(invalid) != {"schema", "semantic"}:
        raise FixtureError("Fixture invalidMaps object is invalid")
    for category in ("schema", "semantic"):
        paths = invalid.get(category)
        if not isinstance(paths, list) or not paths or len(paths) != len(set(paths)):
            raise FixtureError(
                f"Fixture invalidMaps.{category} must be a non-empty unique list"
            )
        if not all(isinstance(item, str) and item for item in paths):
            raise FixtureError(
                f"Fixture invalidMaps.{category} contains an invalid path"
            )
    process_data = files.get("processData")
    if not isinstance(process_data, dict) or set(process_data) != PROCESS_DATA_FIELDS:
        raise FixtureError("Fixture processData object has invalid fields")
    referenced = _fixture_paths(files)
    actual_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "fixture.json"
    }
    if referenced != actual_files:
        raise FixtureError(
            "Fixture metadata does not reference exactly the fixture file set"
        )
    for relative in referenced:
        candidate = root / relative
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise FixtureError(f"Unsafe fixture path: {relative}")
        if not candidate.is_file() or not _inside(candidate, root):
            raise FixtureError(f"Missing fixture path: {relative}")
    digest = value.get("digest")
    if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise FixtureError("Fixture digest has invalid syntax")
    actual_digest = canonical_fixture_digest(root)
    if digest != PUBLISHED_FIXTURE_DIGEST or actual_digest != PUBLISHED_FIXTURE_DIGEST:
        raise FixtureError("Fixture digest differs from the published checker fixture")
    for field in ("module", "action", "targetSchema", "targetFunction", "effectTable"):
        if re.fullmatch(r"[a-z][a-z0-9_]{0,62}", str(value.get(field, ""))) is None:
            raise FixtureError(f"Fixture identifier {field} is invalid")
    return value


def extract_cli_json(stdout: str) -> dict[str, Any] | None:
    """Return one exact JSON object from CLI stdout."""

    text = stdout.strip()
    if not text:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def parse_failpoint_acks(log_text: str, expected_name: str) -> list[dict[str, str]]:
    decoder = json.JSONDecoder()
    result: list[dict[str, str]] = []
    for line in log_text.splitlines():
        start = line.find("{")
        if start < 0:
            continue
        try:
            value, _ = decoder.raw_decode(line[start:])
        except json.JSONDecodeError:
            continue
        if (
            isinstance(value, dict)
            and value.get("event") == "failpoint.reached"
            and value.get("name") == expected_name
            and isinstance(value.get("instanceId"), str)
            and value["instanceId"]
        ):
            result.append(
                {
                    "event": "failpoint.reached",
                    "name": expected_name,
                    "instanceId": value["instanceId"],
                }
            )
    return result


def validate_read_only_query(
    query: str, allowed_fixture_relation: tuple[str, str] | None = None
) -> None:
    if not query.strip() or ";" in query or "--" in query or "/*" in query:
        raise ValueError("Query must be one comment-free statement")
    if re.match(r"^\s*(?:select|with)\b", query, re.IGNORECASE) is None:
        raise ValueError("Query must start with SELECT or WITH")
    scrubbed = _SQL_STRING_LITERAL.sub("", query)
    if "'" in scrubbed:
        raise ValueError("Query contains an unterminated string literal")
    if _WRITE_WORD.search(scrubbed):
        raise ValueError("Query must be read-only")
    references = {
        (schema.casefold(), relation.casefold())
        for schema, relation in re.findall(
            r"\b(?:from|join)\s+([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\b",
            query,
            re.IGNORECASE,
        )
    }
    allowed = {("autocheck", view) for view in AUTOCHECK_VIEWS}
    if allowed_fixture_relation is not None:
        allowed.add(tuple(value.casefold() for value in allowed_fixture_relation))
    relation_references = {item for item in references if item[0] not in {"pg_catalog"}}
    if not references or not relation_references.issubset(allowed):
        raise ValueError("Query references a non-contract relation")


def exact_active_version(rows: Sequence[dict[str, Any]], expected: int) -> bool:
    versions = {row.get("flow_version"): row for row in rows}
    active = {row.get("flow_version") for row in rows if row.get("is_active") is True}
    return (
        len(versions) == len(rows)
        and {1, expected}.issubset(versions)
        and active == {expected}
        and versions[expected].get("status") == "PUBLISHED"
    )


def process_state_matches(
    row: dict[str, Any], state: str, current_step: str | None = None
) -> bool:
    return row.get("state") == state and (
        current_step is None or row.get("current_step_key") == current_step
    )


def strictly_increasing_integer(current: Any, previous: Any) -> bool:
    return (
        isinstance(current, int)
        and not isinstance(current, bool)
        and isinstance(previous, int)
        and not isinstance(previous, bool)
        and current > previous
    )


def stable_view_schemas_match(rows: Sequence[dict[str, Any]]) -> bool:
    actual: dict[str, dict[str, str]] = {}
    for row in rows:
        view = row.get("view_name")
        column = row.get("column_name")
        data_type = row.get("data_type")
        if (
            view not in AUTOCHECK_VIEW_SCHEMAS
            or row.get("relation_kind") != "v"
            or not isinstance(column, str)
            or not isinstance(data_type, str)
        ):
            return False
        columns = actual.setdefault(str(view), {})
        if column in columns:
            return False
        columns[column] = data_type
    return all(
        view in actual
        and all(actual[view].get(column) == data_type for column, data_type in columns)
        for view, columns in AUTOCHECK_VIEW_SCHEMAS.items()
    )


def action_dispatch_matches(
    row: dict[str, Any], *, execution_id: str, module: str, action: str, outcome: str
) -> bool:
    return (
        row.get("request_id") == execution_id
        and row.get("module") == module
        and row.get("action") == action
        and row.get("version") == 1
        and row.get("principal") == "workflow-worker"
        and row.get("status") == "OK"
        and row.get("outcome") == outcome
    )


def job_attempts_consistent(
    job: dict[str, Any], attempts: Sequence[dict[str, Any]], expected_outcome: str
) -> bool:
    count = job.get("attempt_count")
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 1
        or len(attempts) != count
    ):
        return False
    numbers = [row.get("attempt_number") for row in attempts]
    leases = [row.get("lease_version") for row in attempts]
    if numbers != list(range(1, count + 1)):
        return False
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in leases):
        return False
    if leases != sorted(set(leases)) or leases[-1] != job.get("lease_version"):
        return False
    if len({row.get("attempt_id") for row in attempts}) != count:
        return False
    if any(
        row.get("job_id") != job.get("job_id")
        or row.get("execution_id") != job.get("execution_id")
        or not row.get("started_at")
        or not row.get("finished_at")
        for row in attempts
    ):
        return False
    for row in attempts:
        try:
            started = dt.datetime.fromisoformat(
                str(row["started_at"]).replace("Z", "+00:00")
            )
            finished = dt.datetime.fromisoformat(
                str(row["finished_at"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError):
            return False
        try:
            invalid_order = started > finished
        except TypeError:
            return False
        if invalid_order:
            return False
        if row.get("status") == "FAILED":
            if row.get("outcome") is not None or not isinstance(
                row.get("error_code"), str
            ):
                return False
        elif row.get("status") == "SUCCEEDED":
            if (
                row.get("outcome") != expected_outcome
                or row.get("error_code") is not None
            ):
                return False
        else:
            return False
    return (
        job.get("state") == "SUCCEEDED"
        and sum(row.get("status") == "SUCCEEDED" for row in attempts) == 1
        and attempts[-1].get("status") == "SUCCEEDED"
        and attempts[-1].get("outcome") == expected_outcome
        and attempts[-1].get("error_code") is None
    )


def terminal_failure_consistent(
    process: dict[str, Any],
    jobs: Sequence[dict[str, Any]],
    attempts: Sequence[dict[str, Any]],
    effects: Sequence[dict[str, Any]],
    *,
    expected_attempts: int,
    expected_error: str | None = None,
) -> bool:
    if (
        process.get("state") != "FAILED"
        or len(jobs) != 1
        or jobs[0].get("state") != "DEAD"
        or jobs[0].get("attempt_count") != expected_attempts
        or len(attempts) != expected_attempts
        or effects
    ):
        return False
    job = jobs[0]
    leases = [row.get("lease_version") for row in attempts]
    if not all(
        isinstance(value, int) and not isinstance(value, bool) for value in leases
    ):
        return False
    if leases != sorted(set(leases)) or leases[-1] != job.get("lease_version"):
        return False
    for row in attempts:
        try:
            started = dt.datetime.fromisoformat(
                str(row["started_at"]).replace("Z", "+00:00")
            )
            finished = dt.datetime.fromisoformat(
                str(row["finished_at"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError):
            return False
        try:
            invalid_order = started > finished
        except TypeError:
            return False
        if invalid_order:
            return False
    return (
        [row.get("attempt_number") for row in attempts]
        == list(range(1, expected_attempts + 1))
        and len({row.get("attempt_id") for row in attempts}) == expected_attempts
        and all(
            row.get("status") == "FAILED"
            and row.get("job_id") == job.get("job_id")
            and row.get("execution_id") == job.get("execution_id")
            and row.get("outcome") is None
            and isinstance(row.get("error_code"), str)
            and bool(row.get("error_code"))
            and (expected_error is None or row.get("error_code") == expected_error)
            for row in attempts
        )
    )


def _redact(value: Any, sensitive: Sequence[str] = (), depth: int = 0) -> Any:
    if depth > 7:
        return "<depth-limited>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, child in list(value.items())[:200]:
            key = str(raw_key)[:100]
            result[key] = (
                "<redacted>"
                if _SECRET_KEY.search(key)
                else _redact(child, sensitive, depth + 1)
            )
        return result
    if isinstance(value, (list, tuple, set)):
        return [_redact(child, sensitive, depth + 1) for child in list(value)[:200]]
    if isinstance(value, str):
        rendered = value
        for item in sensitive:
            if item:
                rendered = rendered.replace(item, "<redacted>")
        return rendered if len(rendered) <= 1000 else rendered[:997] + "..."
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:1000]


def report_has_forbidden_keys(report: Any) -> bool:
    blocked = {
        ("sc" + "ore").casefold(),
        ("poi" + "nts").casefold(),
        ("criter" + "ionId").casefold(),
        ("evid" + "enceId").casefold(),
        ("diagnostic" + "Code").casefold(),
    }
    if isinstance(report, dict):
        return any(
            str(key).casefold() in blocked or report_has_forbidden_keys(value)
            for key, value in report.items()
        )
    if isinstance(report, list):
        return any(report_has_forbidden_keys(value) for value in report)
    return False


def build_report(
    *,
    started_at: str,
    finished_at: str,
    status: str,
    checks: Sequence[dict[str, Any]],
    commands: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    failed = [item["name"] for item in checks if item.get("status") != "passed"]
    return {
        "manifestVersion": MANIFEST_VERSION,
        "toolVersion": TOOL_VERSION,
        "timestamps": {"startedAt": started_at, "finishedAt": finished_at},
        "status": status,
        "checks": list(checks),
        "failedChecks": failed,
        "commands": list(commands),
    }


def _sql_literal(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_.:-]{1,180}", value) is None:
        raise ContractError("Candidate returned an unsafe identifier")
    return "'" + value + "'"


def _normalize_image_id(value: str) -> str:
    match = re.fullmatch(r"sha256:([a-f0-9]{64})\s*", value)
    if match is None:
        raise ContractError("Compose did not return one full image ID")
    return "sha256:" + match.group(1)


def _published_ports(service: Any) -> set[int]:
    if not isinstance(service, dict):
        return set()
    result: set[int] = set()
    for entry in service.get("ports", []) or []:
        value: Any = None
        if isinstance(entry, dict):
            value = entry.get("published")
        elif isinstance(entry, (str, int)):
            parts = str(entry).rsplit(":", 2)
            value = parts[-2] if len(parts) >= 2 else None
        try:
            result.add(int(value))
        except (TypeError, ValueError):
            result.add(0)
    return result


def _volume_source(value: Any) -> tuple[str | None, str | None, bool]:
    if isinstance(value, dict):
        return value.get("type"), value.get("source"), value.get("read_only") is True
    if not isinstance(value, str):
        return None, None, False
    parts = value.split(":")
    if len(parts) < 2:
        return "volume", value, False
    source = parts[0]
    kind = "bind" if source.startswith(("/", ".", "~")) else "volume"
    options = parts[2].split(",") if len(parts) > 2 else []
    return kind, source, "ro" in options


def _candidate_path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def _raw_compose_findings(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return [f"Compose file is unreadable: {error}"]
    findings: list[str] = []
    for field in ("include", "extends"):
        if re.search(rf"(?m)(?:^|[{{,])\s*(?:{field}|[\"']{field}[\"'])\s*:", text):
            findings.append(f"Compose {field} is not allowed by the checker sandbox")
    return findings


def _unsafe_compose_findings(config: dict[str, Any], repo: Path) -> list[str]:
    findings: list[str] = []
    services = config.get("services")
    services = services if isinstance(services, dict) else {}
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        if service.get("privileged") is True:
            findings.append(f"{name}: privileged")
        for field in ("network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup"):
            value = str(service.get(field, ""))
            if (
                value.casefold() == "host"
                or value.casefold().startswith("container:")
                or "${" in value
            ):
                findings.append(f"{name}: unsafe {field}")
        if (
            service.get("devices")
            or service.get("device_cgroup_rules")
            or service.get("gpus")
            or service.get("cap_add")
            or service.get("runtime")
        ):
            findings.append(f"{name}: elevated device/capability access")
        if service.get("use_api_socket"):
            findings.append(f"{name}: Docker API socket access")
        if service.get("volumes_from"):
            findings.append(f"{name}: volumes_from")
        if service.get("provider"):
            findings.append(f"{name}: external service provider")
        if service.get("external_links"):
            findings.append(f"{name}: external_links")
        logging = service.get("logging") or {}
        if isinstance(logging, dict) and str(
            logging.get("driver", "")
        ).casefold() not in {
            "",
            "json-file",
            "local",
        }:
            findings.append(f"{name}: external logging driver")
        if service.get("credential_spec"):
            findings.append(f"{name}: credential_spec")
        for option in service.get("security_opt", []) or []:
            if "unconfined" in str(option).casefold():
                findings.append(f"{name}: unconfined security option")
        for volume in service.get("volumes", []) or []:
            kind, source, _read_only = _volume_source(volume)
            if not source:
                continue
            if "${" in str(source):
                findings.append(f"{name}: interpolated volume source")
            if "docker.sock" in str(source).casefold():
                findings.append(f"{name}: Docker socket mount")
            if kind == "bind":
                source_path = _candidate_path(str(source), repo)
                if not _inside(source_path, repo):
                    findings.append(f"{name}: external bind mount")
                else:
                    findings.append(f"{name}: repository bind mount")

        build = service.get("build")
        if build:
            context = build.get("context", ".") if isinstance(build, dict) else build
            context_text = str(context)
            context_path = _candidate_path(context_text, repo)
            if (
                "${" in context_text
                or "://" in context_text
                or context_text.startswith("git@")
                or not _inside(context_path, repo)
            ):
                findings.append(f"{name}: external build context")
            if isinstance(build, dict):
                dockerfile = build.get("dockerfile")
                if dockerfile and (
                    "${" in str(dockerfile)
                    or "://" in str(dockerfile)
                    or not _inside(_candidate_path(str(dockerfile), context_path), repo)
                ):
                    findings.append(f"{name}: external Dockerfile")
                if build.get("privileged") or build.get("ssh") or build.get("secrets"):
                    findings.append(f"{name}: unsafe build privilege/secret option")
                if build.get("tags") or build.get("cache_to") or build.get("output"):
                    findings.append(f"{name}: unsafe build exporter/tag option")
                if str(build.get("network", "")).casefold() == "host":
                    findings.append(f"{name}: host build network")
                entitlements = {
                    str(item).casefold() for item in build.get("entitlements", []) or []
                }
                if entitlements.intersection({"network.host", "security.insecure"}):
                    findings.append(f"{name}: unsafe build entitlement")
                additional = build.get("additional_contexts", {}) or {}
                sources = (
                    additional.values() if isinstance(additional, dict) else additional
                )
                for entry in sources:
                    source = str(entry).split("=", 1)[-1]
                    if source.startswith(("service:", "docker-image://")):
                        continue
                    if (
                        "${" in source
                        or "://" in source
                        or not _inside(_candidate_path(source, repo), repo)
                    ):
                        findings.append(f"{name}: external additional build context")

        env_files = service.get("env_file", []) or []
        if isinstance(env_files, (str, dict)):
            env_files = [env_files]
        for entry in env_files:
            value = entry.get("path") if isinstance(entry, dict) else entry
            if value and (
                "${" in str(value)
                or "://" in str(value)
                or not _inside(_candidate_path(str(value), repo), repo)
            ):
                findings.append(f"{name}: external env_file")

    for section in ("volumes", "networks", "configs", "secrets"):
        resources = config.get(section, {}) or {}
        if not isinstance(resources, dict):
            findings.append(f"invalid top-level {section}")
            continue
        for name, resource in resources.items():
            if not isinstance(resource, dict):
                continue
            if resource.get("external") is True:
                findings.append(f"{section}.{name}: external resource")
            driver = str(resource.get("driver", "")).casefold()
            driver_options = resource.get("driver_opts") or {}
            if section == "volumes" and (driver not in {"", "local"} or driver_options):
                findings.append(f"{section}.{name}: unsafe volume driver/options")
            if section == "networks" and driver not in {"", "bridge"}:
                findings.append(f"{section}.{name}: unsafe network driver")
            if section == "networks" and (
                resource.get("driver_opts") or resource.get("ipam")
            ):
                findings.append(f"{section}.{name}: unsafe network options")
            if section in {"configs", "secrets"} and driver:
                findings.append(f"{section}.{name}: unsafe resource driver")
            source = resource.get("file")
            if source:
                if not _inside(_candidate_path(str(source), repo), repo):
                    findings.append(f"{section}.{name}: external file")
                elif section in {"configs", "secrets"}:
                    findings.append(f"{section}.{name}: repository file mount")
    return sorted(set(findings))


def _dotnet_build_declared(service: Any, repo: Path) -> bool:
    if not isinstance(service, dict):
        return False
    build = service.get("build")
    if not build:
        return False
    if isinstance(build, dict) and isinstance(build.get("dockerfile_inline"), str):
        dockerfile_text = build["dockerfile_inline"]
    else:
        context_value = build.get("context", ".") if isinstance(build, dict) else build
        context = Path(str(context_value)).expanduser()
        if not context.is_absolute():
            context = repo / context
        dockerfile_value = (
            build.get("dockerfile", "Dockerfile")
            if isinstance(build, dict)
            else "Dockerfile"
        )
        dockerfile = Path(str(dockerfile_value)).expanduser()
        if not dockerfile.is_absolute():
            dockerfile = context / dockerfile
        if not _inside(context, repo) or not _inside(dockerfile, repo):
            return False
        try:
            dockerfile_text = dockerfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    stages = list(
        re.finditer(
            r"(?im)^\s*FROM(?:\s+--platform=\S+)?\s+(\S+)"
            r"(?:\s+AS\s+(\S+))?.*$",
            dockerfile_text,
        )
    )
    if not stages:
        return False
    images = [match.group(1) for match in stages]
    aliases = {
        match.group(2).casefold(): match.group(1) for match in stages if match.group(2)
    }
    target = build.get("target") if isinstance(build, dict) else None
    if target:
        selected = next(
            (
                index
                for index, match in enumerate(stages)
                if match.group(2)
                and match.group(2).casefold() == str(target).casefold()
            ),
            None,
        )
        if selected is None:
            return False
    else:
        selected = len(stages) - 1
    block_end = (
        stages[selected + 1].start()
        if selected + 1 < len(stages)
        else len(dockerfile_text)
    )
    final_block = dockerfile_text[stages[selected].end() : block_end]

    def resolve_source(source: str) -> str:
        current = source
        visited: set[str] = set()
        while current.casefold() in aliases and current.casefold() not in visited:
            visited.add(current.casefold())
            current = aliases[current.casefold()]
        return current

    runtime_command = " ".join(
        str(value)
        for value in (service.get("entrypoint"), service.get("command"))
        if value is not None
    )
    if not runtime_command:
        runtime_command = "\n".join(
            re.findall(r"(?im)^\s*(?:ENTRYPOINT|CMD)\s+(.+)$", final_block)
        )
    project_names: set[str] = set()
    for project in repo.rglob("*.csproj"):
        if not _inside(project, repo):
            continue
        project_names.add(project.stem.casefold())
        try:
            project_text = project.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        project_names.update(
            value.strip().casefold()
            for value in re.findall(
                r"(?is)<AssemblyName>\s*([^<]+?)\s*</AssemblyName>", project_text
            )
        )
    command_text = runtime_command.casefold()
    recognized_command = bool(
        re.search(r"(?i)(?:\bdotnet\b|\.dll\b)", runtime_command)
        or any(
            re.search(
                rf"(?:^|[\s\[\"'/]){re.escape(name)}(?:$|[\s,\]\"'])",
                command_text,
            )
            for name in project_names
        )
    )
    final_base_is_dotnet = (
        "mcr.microsoft.com/dotnet/" in resolve_source(images[selected]).casefold()
    )
    copied_entrypoint_from_dotnet = False
    copied_entrypoint_from_non_dotnet = False
    for match in re.finditer(r"(?im)^\s*COPY\s+--from=([^\s]+)\s+(.+)$", final_block):
        source = resolve_source(match.group(1))
        destination = match.group(2).rsplit(maxsplit=1)[-1].strip("\"',[]")
        destination = destination.rstrip("/").casefold()
        if destination and destination in command_text:
            if "mcr.microsoft.com/dotnet/" in source.casefold():
                copied_entrypoint_from_dotnet = True
            else:
                copied_entrypoint_from_non_dotnet = True
    dotnet_lineage = final_base_is_dotnet or copied_entrypoint_from_dotnet
    return (
        dotnet_lineage
        and recognized_command
        and not copied_entrypoint_from_non_dotnet
        and not bool(
            re.search(r"(?i)\b(?:python\d*|node|java|ruby|php)\b", runtime_command)
        )
    )


class ComposeHarness:
    def __init__(
        self,
        *,
        repo: Path,
        fixtures: Path,
        compose_file: Path,
        compose_wrapper: Path,
        override_file: Path,
        project: str,
        gateway_port: int,
        sensitive: Sequence[str],
    ) -> None:
        self.repo = repo
        self.fixtures = fixtures
        self.compose_file = compose_file
        self.compose_wrapper = compose_wrapper
        self.override_file = override_file
        self.project = project
        self.gateway_port = gateway_port
        self.sensitive = tuple(item for item in sensitive if item)
        self.commands: list[dict[str, Any]] = []

    def _environment(self, failpoint: str = "") -> dict[str, str]:
        environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": os.environ.get("HOME", str(Path.home())),
            "COURSE_GATEWAY_PORT": str(self.gateway_port),
            "COURSE_TEST_PROFILE": "1",
            "COURSE_FAILPOINT": failpoint,
            "COMPOSE_DISABLE_ENV_FILE": "1",
        }
        for key in ("DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"):
            if key in os.environ:
                environment[key] = os.environ[key]
        return environment

    def _redacted_command(self, command: Sequence[str]) -> list[str]:
        replacements = {
            str(self.repo): "<repo>",
            str(self.fixtures): "<fixtures>",
            str(self.override_file): "<trusted-override>",
        }
        rendered: list[str] = []
        hide_next = False
        for part in command:
            value = str(part)
            if hide_next:
                rendered.append("<read-only-query>")
                hide_next = False
                continue
            for original, replacement in replacements.items():
                value = value.replace(original, replacement)
            for item in self.sensitive:
                value = value.replace(item, "<redacted>")
            rendered.append(value)
            if value == "-c":
                hide_next = True
        return rendered

    def run(
        self,
        command: Sequence[str],
        *,
        timeout: float,
        input_text: str | None = None,
        failpoint: str = "",
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                [str(part) for part in command],
                cwd=self.repo,
                env=self._environment(failpoint),
                text=True,
                input=input_text,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            result = CommandResult(
                tuple(str(part) for part in command),
                completed.returncode,
                completed.stdout,
                completed.stderr,
            )
        except subprocess.TimeoutExpired as error:
            stdout = (
                error.stdout.decode()
                if isinstance(error.stdout, bytes)
                else error.stdout
            )
            stderr = (
                error.stderr.decode()
                if isinstance(error.stderr, bytes)
                else error.stderr
            )
            result = CommandResult(
                tuple(str(part) for part in command),
                124,
                stdout or "",
                stderr or "",
                True,
            )
        except OSError as error:
            result = CommandResult(
                tuple(str(part) for part in command), 127, "", str(error)
            )
        self.commands.append(
            {
                "command": self._redacted_command(result.command),
                "exitCode": result.returncode,
                "timedOut": result.timed_out,
            }
        )
        return result

    def compose(
        self,
        arguments: Sequence[str],
        *,
        timeout: float = 60,
        input_text: str | None = None,
        failpoint: str = "",
    ) -> CommandResult:
        command = [
            "bash",
            str(self.compose_wrapper),
            "--project-name",
            self.project,
            "-f",
            str(self.compose_file),
            "-f",
            str(self.override_file),
            *arguments,
        ]
        return self.run(
            command, timeout=timeout, input_text=input_text, failpoint=failpoint
        )

    def compose_candidate(
        self, arguments: Sequence[str], *, timeout: float = 60
    ) -> CommandResult:
        return self.run(
            [
                "bash",
                str(self.compose_wrapper),
                "--project-name",
                self.project,
                "-f",
                str(self.compose_file),
                *arguments,
            ],
            timeout=timeout,
        )

    @staticmethod
    def _environment_error(result: CommandResult) -> bool:
        return result.returncode == 127 or bool(
            _TRANSPORT_ERROR.search(result.stdout + "\n" + result.stderr)
        )

    def require(self, result: CommandResult, message: str) -> None:
        if result.ok:
            return
        if self._environment_error(result):
            raise EnvironmentFailure(message)
        suffix = " (timed out)" if result.timed_out else f" (exit {result.returncode})"
        raise ContractError(message + suffix)

    def cli(
        self, *arguments: str, timeout: float = 120, input_text: str | None = None
    ) -> tuple[CommandResult, dict[str, Any] | None]:
        result = self.compose(
            [
                "run",
                "--rm",
                "-T",
                "--no-deps",
                "-v",
                f"{self.fixtures}:/autocheck/input:ro",
                "cli",
                *arguments,
            ],
            timeout=timeout,
            input_text=input_text,
        )
        if self._environment_error(result):
            raise EnvironmentFailure(
                "Docker transport failed while running the trusted CLI adapter"
            )
        return result, extract_cli_json(result.stdout)

    @staticmethod
    def ok_envelope(result: CommandResult, body: dict[str, Any] | None) -> bool:
        return (
            result.ok
            and isinstance(body, dict)
            and body.get("status") == "ok"
            and isinstance(body.get("meta"), dict)
            and body["meta"].get("contractVersion") == "course-1"
        )

    @staticmethod
    def error_envelope(result: CommandResult, body: dict[str, Any] | None) -> bool:
        return (
            not result.ok
            and isinstance(body, dict)
            and body.get("status") == "error"
            and isinstance(body.get("code"), str)
            and bool(body.get("code"))
            and isinstance(body.get("meta"), dict)
            and body["meta"].get("contractVersion") == "course-1"
        )

    @staticmethod
    def error_code(body: dict[str, Any] | None) -> str | None:
        value = body.get("code") if isinstance(body, dict) else None
        return value if isinstance(value, str) else None

    def _psql_rows(
        self,
        query: str,
        *,
        allowed_fixture_relation: tuple[str, str] | None = None,
        timeout: float = 10,
        container_id: str | None = None,
    ) -> list[dict[str, Any]]:
        validate_read_only_query(query, allowed_fixture_relation)
        wrapped = (
            "SELECT COALESCE(jsonb_agg(to_jsonb(q)), '[]'::jsonb)::text "
            f"FROM ({query}) AS q"
        )
        psql = [
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "course",
            "-At",
            "-c",
            wrapped,
        ]
        if container_id is None:
            result = self.compose(["exec", "-T", "postgres", *psql], timeout=timeout)
        else:
            if re.fullmatch(r"[a-f0-9]{12,64}", container_id) is None:
                raise ValueError("PostgreSQL container id is invalid")
            result = self.run(["docker", "exec", container_id, *psql], timeout=timeout)
        if not result.ok:
            if self._environment_error(result):
                raise EnvironmentFailure(
                    "PostgreSQL transport failed during a stable-view query"
                )
            raise ContractError("A required read-only PostgreSQL contract query failed")
        try:
            value = json.loads(result.stdout.strip())
        except json.JSONDecodeError as error:
            raise ContractError(
                "A required PostgreSQL view did not return JSON rows"
            ) from error
        if not isinstance(value, list) or not all(
            isinstance(row, dict) for row in value
        ):
            raise ContractError(
                "A required PostgreSQL view returned an invalid row shape"
            )
        return value

    def psql_rows(
        self, query: str, timeout: float = 10, *, container_id: str | None = None
    ) -> list[dict[str, Any]]:
        return self._psql_rows(query, timeout=timeout, container_id=container_id)

    @staticmethod
    def _container_addresses(result: CommandResult) -> set[str]:
        if not result.ok:
            return set()
        addresses: set[str] = set()
        for value in result.stdout.split():
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    socket.inet_pton(family, value)
                except OSError:
                    continue
                addresses.add(value)
                break
        return addresses

    def _service_addresses(self, service: str) -> tuple[bool, set[str]]:
        containers = self.compose(["ps", "-q", service], timeout=10)
        if not containers.ok:
            if self._environment_error(containers):
                raise EnvironmentFailure(
                    "Docker transport failed during the worker address probe"
                )
            return False, set()
        container_ids = [
            item.strip() for item in containers.stdout.splitlines() if item.strip()
        ]
        if (
            len(container_ids) != 1
            or re.fullmatch(r"[a-f0-9]{12,64}", container_ids[0]) is None
        ):
            return False, set()
        inspected = self.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{println .IPAddress}}{{println .GlobalIPv6Address}}{{end}}",
                container_ids[0],
            ],
            timeout=10,
        )
        if not inspected.ok and self._environment_error(inspected):
            raise EnvironmentFailure(
                "Docker transport failed during the worker address probe"
            )
        addresses = self._container_addresses(inspected)
        return inspected.ok and bool(addresses), addresses

    def service_container_ids(
        self, services: Sequence[str], *, include_stopped: bool = False
    ) -> dict[str, str]:
        arguments = ["ps", "-aq" if include_stopped else "-q"]
        result: dict[str, str] = {}
        for service in services:
            containers = self.compose([*arguments, service], timeout=10)
            self.require(containers, f"Cannot resolve the {service} container")
            values = [
                item.strip() for item in containers.stdout.splitlines() if item.strip()
            ]
            if len(values) != 1 or re.fullmatch(r"[a-f0-9]{12,64}", values[0]) is None:
                raise ContractError(f"Expected exactly one {service} container")
            result[service] = values[0]
        return result

    def worker_database_security(self) -> dict[str, Any]:
        service_addresses: dict[str, set[str]] = {}
        address_probes: dict[str, bool] = {}
        for service in ("worker-a", "worker-b"):
            address_probes[service], service_addresses[service] = (
                self._service_addresses(service)
            )

        addresses = sorted(
            {address for values in service_addresses.values() for address in values}
        )
        sessions: list[dict[str, Any]] = []
        if addresses:
            literals = ", ".join(_sql_literal(address) for address in addresses)
            sessions = self.psql_rows(
                "SELECT host(client_addr) AS client_addr, usename AS session_role, "
                "count(*)::integer AS session_count FROM pg_catalog.pg_stat_activity "
                "WHERE datname = current_database() AND client_addr IS NOT NULL "
                f"AND host(client_addr) IN ({literals}) "
                "GROUP BY host(client_addr), usename ORDER BY host(client_addr), usename"
            )

        physical_tables = self.psql_rows(
            "WITH worker_role AS ("
            "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'workflow_worker'"
            ") SELECT n.nspname AS schema_name, c.relname AS table_name, "
            "has_table_privilege(r.oid, c.oid, 'INSERT') AS has_insert, "
            "has_table_privilege(r.oid, c.oid, 'UPDATE') AS has_update, "
            "has_table_privilege(r.oid, c.oid, 'DELETE') AS has_delete "
            "FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "LEFT JOIN worker_role r ON true "
            "WHERE c.relkind IN ('r', 'p', 'f') "
            "AND n.nspname <> 'information_schema' "
            "AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' "
            "ORDER BY n.nspname, c.relname"
        )
        function_privileges = self.psql_rows(
            "WITH worker_role AS ("
            "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'workflow_worker'"
            ") SELECT n.nspname AS schema_name, p.proname AS function_name, "
            "has_function_privilege(r.oid, p.oid, 'EXECUTE') AS can_execute "
            "FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "LEFT JOIN worker_role r ON true "
            "WHERE n.nspname IN ('api', 'workflow') "
            "ORDER BY n.nspname, p.proname, p.oid"
        )
        allowed_boundaries = {
            ("api", "invoke"),
            ("workflow", "claim_jobs"),
            ("workflow", "finish_job"),
            ("workflow", "fail_job"),
        }
        executable_boundaries = {
            (str(row.get("schema_name")), str(row.get("function_name")))
            for row in function_privileges
            if row.get("can_execute") is True
        }
        services: dict[str, dict[str, Any]] = {}
        for service, service_ips in service_addresses.items():
            roles = sorted(
                {
                    str(row["session_role"])
                    for row in sessions
                    if row.get("client_addr") in service_ips
                    and isinstance(row.get("session_role"), str)
                }
            )
            services[service] = {
                "addressProbe": address_probes[service],
                "addressCount": len(service_ips),
                "sessionRoles": roles,
                "roleVerified": roles == ["workflow_worker"],
            }
        return {
            "services": services,
            "roleVerified": all(item["roleVerified"] for item in services.values()),
            "physicalTableCount": len(physical_tables),
            "allDmlDenied": bool(physical_tables)
            and all(
                row.get("has_insert") is False
                and row.get("has_update") is False
                and row.get("has_delete") is False
                for row in physical_tables
            ),
            "executeBoundaryRestricted": executable_boundaries == allowed_boundaries,
            "executableFunctionCount": len(executable_boundaries),
        }

    def wait_worker_database_security(
        self, *, timeout: float = 5, interval: float = 0.1
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        report: dict[str, Any] = {}
        while True:
            report = self.worker_database_security()
            if report.get("roleVerified") is True:
                return report
            now = time.monotonic()
            if now >= deadline:
                return report
            time.sleep(min(interval, max(0.0, deadline - now)))

    def effect_rows(
        self, schema: str, table: str, execution_id: str | None = None
    ) -> list[dict[str, Any]]:
        for value in (schema, table):
            if re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is None:
                raise ValueError("Unsafe fixture relation identifier")
        where = (
            ""
            if execution_id is None
            else f" WHERE execution_id = {_sql_literal(execution_id)}"
        )
        return self._psql_rows(
            "SELECT execution_id, business_value, created_at "
            f"FROM {schema}.{table}{where} ORDER BY execution_id",
            allowed_fixture_relation=(schema, table),
        )

    def image_id(self, service: str) -> str:
        config = self.compose(
            ["config", "--format", "json", "--no-env-resolution"], timeout=30
        )
        self.require(config, f"Cannot resolve the {service} image reference")
        try:
            definition = json.loads(config.stdout)["services"][service]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ContractError(
                f"Compose did not return an image reference for {service}"
            ) from error
        reference = definition.get("image") if isinstance(definition, dict) else None
        if (
            reference is None
            and isinstance(definition, dict)
            and definition.get("build")
        ):
            reference = f"{self.project}-{service}"
        if not isinstance(reference, str) or not reference or "\n" in reference:
            raise ContractError(
                f"Compose returned an invalid image reference for {service}"
            )
        result = self.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
            timeout=30,
        )
        self.require(result, f"Cannot inspect the {service} image ID")
        return _normalize_image_id(result.stdout)

    def wait_ready(self, timeout: float, interval: float = 0.1) -> bool:
        if interval <= 0 or interval > 0.1:
            raise ValueError("Readiness polling interval must not exceed 100 ms")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + timeout
        while True:
            statuses: list[int] = []
            for path in ("/health/live", "/health/ready"):
                try:
                    with opener.open(
                        f"http://127.0.0.1:{self.gateway_port}{path}", timeout=2
                    ) as response:
                        statuses.append(response.status)
                except (urllib.error.URLError, TimeoutError, OSError):
                    statuses.append(0)
            if statuses == [200, 200]:
                return True
            now = time.monotonic()
            if now >= deadline:
                return False
            time.sleep(min(interval, max(0.0, deadline - now)))

    def post_action(
        self, module: str, action: str, payload: dict[str, Any], scopes: Sequence[str]
    ) -> HttpResult:
        token = issue_token(self.sensitive[0], "public-check-client", scopes)
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.gateway_port}/api/{module}/{action}",
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Idempotency-Key": f"public-check-{uuid.uuid4()}",
            },
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=10) as response:
                status = response.status
                raw = response.read(1_048_577)
        except urllib.error.HTTPError as error:
            status = error.code
            raw = error.read(1_048_577)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return HttpResult(0, None, f"{type(error).__name__}: {error}")
        if len(raw) > 1_048_576:
            return HttpResult(status, None, "response body exceeded 1 MiB")
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = None
        return HttpResult(status, body if isinstance(body, dict) else None)

    def poll_rows(
        self,
        query: str,
        predicate: Callable[[list[dict[str, Any]]], bool],
        *,
        timeout: float = 8,
        interval: float = 0.05,
        container_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if interval <= 0 or interval > 0.1:
            raise ValueError("State polling interval must not exceed 100 ms")
        deadline = time.monotonic() + timeout
        while True:
            rows = self.psql_rows(
                query, timeout=min(10, timeout), container_id=container_id
            )
            if predicate(rows):
                return rows
            now = time.monotonic()
            if now >= deadline:
                raise ContractError(
                    "A required state predicate was not reached before its deadline"
                )
            time.sleep(min(interval, max(0.0, deadline - now)))

    def wait_failpoint(
        self,
        service: str,
        name: str,
        *,
        timeout: float = 8,
        interval: float = 0.05,
        container_id: str | None = None,
    ) -> dict[str, str]:
        if interval <= 0 or interval > 0.1:
            raise ValueError("Failpoint polling interval must not exceed 100 ms")
        deadline = time.monotonic() + timeout
        successful_reads = 0
        while True:
            logs = (
                self.compose(["logs", "--no-color", service], timeout=min(10, timeout))
                if container_id is None
                else self.run(["docker", "logs", container_id], timeout=min(1, timeout))
            )
            if logs.ok:
                successful_reads += 1
                acknowledgements = parse_failpoint_acks(
                    logs.stdout + "\n" + logs.stderr, name
                )
                if len(acknowledgements) > 1:
                    raise ContractError(
                        f"Worker emitted more than one structured {name} acknowledgement"
                    )
                if acknowledgements:
                    return acknowledgements[0]
            elif self._environment_error(logs):
                raise EnvironmentFailure(
                    "Docker logs transport failed during failpoint polling"
                )
            now = time.monotonic()
            if now >= deadline:
                if successful_reads:
                    raise ContractError(
                        f"No structured {name} acknowledgement was emitted"
                    )
                raise EnvironmentFailure(
                    "No worker log read succeeded during failpoint polling"
                )
            time.sleep(min(interval, max(0.0, deadline - now)))

    def wait_single_winner(
        self,
        services: Sequence[str],
        name: str,
        *,
        timeout: float = 8,
        interval: float = 0.05,
        stability: float = 0.2,
    ) -> tuple[str, str, dict[str, str]]:
        if len(services) != 2 or len(set(services)) != 2:
            raise ValueError("Exactly two workers are required")
        deadline = time.monotonic() + timeout
        successful_reads = 0
        observed_winner: str | None = None
        observed_at: float | None = None
        while True:
            remaining = max(0.1, deadline - time.monotonic())
            logs = self.compose(
                ["logs", "--no-color", *services], timeout=min(remaining, 1.0)
            )
            acknowledgements: dict[str, dict[str, str]] = {}
            if logs.ok:
                successful_reads += 1
                parsed = parse_failpoint_acks(logs.stdout + "\n" + logs.stderr, name)
                if any(ack["instanceId"] not in services for ack in parsed):
                    raise ContractError(
                        "A failpoint acknowledgement used an unexpected instanceId"
                    )
                counts = {
                    service: sum(ack["instanceId"] == service for ack in parsed)
                    for service in services
                }
                if any(count > 1 for count in counts.values()):
                    raise ContractError(
                        "A worker emitted more than one claim acknowledgement"
                    )
                acknowledgements = {ack["instanceId"]: ack for ack in parsed}
            elif self._environment_error(logs):
                raise EnvironmentFailure(
                    "Docker logs transport failed during winner polling"
                )
            if len(acknowledgements) > 1:
                raise ContractError(
                    "More than one worker acknowledged one logical job claim"
                )
            if len(acknowledgements) == 1:
                winner, ack = next(iter(acknowledgements.items()))
                now = time.monotonic()
                if observed_winner != winner:
                    observed_winner = winner
                    observed_at = now
                elif observed_at is not None and now - observed_at >= stability:
                    loser = next(service for service in services if service != winner)
                    return winner, loser, ack
            else:
                observed_winner = None
                observed_at = None
            now = time.monotonic()
            if now >= deadline:
                if not successful_reads:
                    raise EnvironmentFailure(
                        "No complete worker log read succeeded during winner polling"
                    )
                raise ContractError(
                    "Neither worker acknowledged the deterministic job claim"
                )
            time.sleep(min(interval, max(0.0, deadline - now)))


class PublicChecker:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.repo = args.repo.expanduser().resolve()
        self.fixtures = args.fixtures.expanduser().resolve()
        self.output = args.output
        self.fixture = load_fixture(self.fixtures)
        self.fixture_digest = canonical_fixture_digest(self.fixtures)
        self.files = self.fixture["files"]
        self.flow = str(self.fixture["flowName"])
        self.module = str(self.fixture["module"])
        self.action = str(self.fixture["action"])
        self.compose_file = self._resolve_compose_file()
        self.compose_wrapper = args.compose_wrapper.expanduser().resolve()
        if not self.compose_wrapper.is_file():
            raise FixtureError("Trusted safe_compose.sh is missing")
        self.temp = Path(tempfile.mkdtemp(prefix="moduledev-week2-public-"))
        self.override = self.temp / "autocheck.override.yaml"
        self.secret = secrets.token_urlsafe(48)
        self.project = f"moduledev-w2-{uuid.uuid4().hex[:12]}"
        self.gateway_port = self._free_port()
        self.cleanup_armed = False
        self.created_image_tags: list[str] = []
        self._write_override()
        self.harness = ComposeHarness(
            repo=self.repo,
            fixtures=self.fixtures,
            compose_file=self.compose_file,
            compose_wrapper=self.compose_wrapper,
            override_file=self.override,
            project=self.project,
            gateway_port=self.gateway_port,
            sensitive=(self.secret,),
        )
        self.checks: list[dict[str, Any]] = []
        self.baseline_images: dict[str, str] = {}
        self.processes: dict[str, str] = {}

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def _resolve_compose_file(self) -> Path:
        if self.args.compose_file is not None:
            path = self.args.compose_file.expanduser()
            path = path if path.is_absolute() else self.repo / path
            path = path.resolve()
            if not path.is_file() or not _inside(path, self.repo):
                raise FixtureError(
                    "Selected Compose file must be inside the repository"
                )
            return path
        for name in COMPOSE_NAMES:
            path = self.repo / name
            if path.is_file():
                return path
        raise ContractError("No root Compose file was found")

    def _write_override(self, config: dict[str, Any] | None = None) -> None:
        services = config.get("services", {}) if config is not None else {}
        services = services if isinstance(services, dict) else {}
        image_overrides: dict[str, str] = {}
        if services:
            built_images = {
                str(service.get("image"))
                for service in services.values()
                if isinstance(service, dict)
                and service.get("build")
                and isinstance(service.get("image"), str)
                and service.get("image")
            }
            aliases = {
                image: f"{self.project}-image-{index}:public-check"
                for index, image in enumerate(sorted(built_images), start=1)
            }
            image_overrides = {
                name: aliases[str(service.get("image"))]
                for name, service in services.items()
                if name in REQUIRED_SERVICES
                and isinstance(service, dict)
                and str(service.get("image")) in aliases
            }
        self.created_image_tags = sorted(set(image_overrides.values()))

        lines = ["services:"]
        common_environment = (
            ("COURSE_JWT_ISSUER", "moduledev-course"),
            ("COURSE_JWT_AUDIENCE", "moduledev-api"),
            ("COURSE_JWT_SIGNING_KEY", self.secret),
            ("COURSE_TEST_PROFILE", "${COURSE_TEST_PROFILE:-1}"),
        )
        service_names = {"api", "cli", "worker-a", "worker-b", "gateway"}
        service_names.update(
            name
            for name, service in services.items()
            if isinstance(service, dict) and service.get("container_name")
        )
        service_names.update(image_overrides)
        for name in sorted(service_names):
            lines.append(f"  {name}:")
            if name in image_overrides:
                lines.append(f"    image: {json.dumps(image_overrides[name])}")
            service = services.get(name)
            if isinstance(service, dict) and service.get("container_name"):
                lines.append("    container_name: !reset null")
            if name in {"api", "cli", "worker-a", "worker-b"}:
                lines.append("    environment:")
                for key, value in common_environment:
                    lines.append(f"      {key}: {json.dumps(value)}")
                if name.startswith("worker-"):
                    lines.append('      COURSE_FAILPOINT: "${COURSE_FAILPOINT:-}"')
            if name == "gateway":
                lines.extend(
                    (
                        "    ports: !override",
                        '      - "127.0.0.1:${COURSE_GATEWAY_PORT:-8080}:8080"',
                    )
                )
        if config is not None:
            for section in ("volumes", "networks", "configs", "secrets"):
                resources = config.get(section, {}) or {}
                if not isinstance(resources, dict) or not resources:
                    continue
                lines.append(f"{section}:")
                for index, name in enumerate(sorted(resources), start=1):
                    lines.extend(
                        (
                            f"  {json.dumps(name)}:",
                            f"    name: {self.project}-{section}-{index}",
                        )
                    )
        content = "\n".join(lines) + "\n"
        self.override.write_text(content, encoding="utf-8")
        os.chmod(self.override, 0o600)

    def record(
        self, name: str, phase: str, passed: bool, expected: Any, actual: Any
    ) -> None:
        if any(item["name"] == name for item in self.checks):
            return
        self.checks.append(
            {
                "name": name,
                "phase": phase,
                "status": "passed" if passed else "failed",
                "expected": _redact(expected, (self.secret,)),
                "actual": _redact(actual, (self.secret,)),
            }
        )

    def fail_missing(self, phase: str, message: str) -> None:
        for name in PHASE_CHECKS[phase]:
            self.record(name, phase, False, "published contract satisfied", message)

    def run_phase(self, phase: str, function: Callable[[], None]) -> None:
        try:
            function()
        except ContractError as error:
            self.fail_missing(phase, str(error))

    @staticmethod
    def _command_view(
        result: CommandResult, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return {
            "exitCode": result.returncode,
            "timedOut": result.timed_out,
            "status": body.get("status") if isinstance(body, dict) else None,
            "code": body.get("code") if isinstance(body, dict) else None,
        }

    def _tracked_paths(self) -> list[str]:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=self.repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            return [item for item in result.stdout.split("\0") if item]
        return [
            path.relative_to(self.repo).as_posix()
            for path in self.repo.rglob("*")
            if path.is_file() and ".git" not in path.parts
        ]

    def _admission_text_findings(self) -> list[str]:
        findings: list[str] = []
        try:
            text = (self.repo / "README.md").read_text(encoding="utf-8")
        except OSError:
            return ["missing README.md"]
        headings = {
            item.strip().casefold()
            for item in re.findall(r"(?mi)^#{2,4}[ \t]+(.+?)[ \t]*$", text)
        }
        findings.extend(
            f"missing README section {name}"
            for name in sorted(SOLUTION_HEADINGS - headings)
        )
        findings.extend(
            f"missing README value {value}"
            for value in README_LITERALS
            if value not in text
        )
        tracked = self._tracked_paths()
        if ".gitignore" not in tracked:
            findings.append("missing .gitignore")
        for item in tracked:
            path = Path(item)
            parts = {part.casefold() for part in path.parts}
            name = path.name.casefold()
            if parts.intersection({"bin", "obj", ".vs", ".idea", "__pycache__"}):
                findings.append(f"tracked generated directory {item}")
            elif name == ".env" or (
                name.startswith(".env.") and name != ".env.example"
            ):
                findings.append(f"tracked environment file {item}")
            elif name == "week-2-public-report.json" or name.endswith(".log"):
                findings.append(f"tracked generated artifact {item}")
        return findings

    def admission(self) -> bool:
        self.record(
            "fixture-integrity",
            "admission",
            True,
            self.fixture["digest"],
            canonical_fixture_digest(self.fixtures),
        )
        text_findings = self._admission_text_findings()
        self.record(
            "repository-contract",
            "admission",
            not text_findings,
            "README sections, launch/check commands and clean tracked artifacts",
            text_findings,
        )
        raw_compose_findings = _raw_compose_findings(self.compose_file)
        if raw_compose_findings:
            self.record(
                "compose-safety",
                "admission",
                False,
                "self-contained Compose model",
                raw_compose_findings,
            )
            return False
        config_result = self.harness.compose_candidate(
            ["config", "--format", "json", "--no-env-resolution"], timeout=60
        )
        if not config_result.ok:
            if self.harness._environment_error(config_result):
                raise EnvironmentFailure(
                    "Docker Compose is unavailable during admission"
                )
            self.record(
                "compose-contract",
                "admission",
                False,
                sorted(REQUIRED_SERVICES),
                {"exitCode": config_result.returncode},
            )
            return False
        try:
            config = json.loads(config_result.stdout)
        except json.JSONDecodeError:
            self.record(
                "compose-contract",
                "admission",
                False,
                "valid Compose JSON",
                "invalid output",
            )
            return False
        services = config.get("services") if isinstance(config, dict) else None
        services = services if isinstance(services, dict) else {}
        gateway_ports = _published_ports(services.get("gateway"))
        other_ports = {
            name: sorted(_published_ports(service))
            for name, service in services.items()
            if name != "gateway" and _published_ports(service)
        }
        missing = sorted(REQUIRED_SERVICES - set(services))
        compose_ok = not missing and gateway_ports == {8080} and not other_ports
        self.record(
            "compose-contract",
            "admission",
            compose_ok,
            {
                "services": sorted(REQUIRED_SERVICES),
                "gatewayPorts": [8080],
                "otherPorts": {},
            },
            {
                "missingServices": missing,
                "gatewayPorts": sorted(gateway_ports),
                "otherPorts": other_ports,
            },
        )
        unsafe = _unsafe_compose_findings(config, self.repo)
        self.record(
            "compose-safety", "admission", not unsafe, "no host escape options", unsafe
        )
        worker_a = services.get("worker-a", {})
        worker_b = services.get("worker-b", {})
        image_a = worker_a.get("image") if isinstance(worker_a, dict) else None
        image_b = worker_b.get("image") if isinstance(worker_b, dict) else None
        worker_declared = (
            isinstance(image_a, str) and bool(image_a) and image_a == image_b
        )
        self.record(
            "worker-image-contract",
            "admission",
            worker_declared,
            "worker-a and worker-b declare one shared image",
            {"sameDeclaredImage": worker_declared},
        )
        api_dotnet = _dotnet_build_declared(services.get("api"), self.repo)
        worker_dotnet = _dotnet_build_declared(
            worker_a, self.repo
        ) or _dotnet_build_declared(worker_b, self.repo)
        self.record(
            "dotnet-runtime-contract",
            "admission",
            api_dotnet and worker_dotnet,
            "api and shared worker are built as .NET runtimes",
            {"apiDotnet": api_dotnet, "workerDotnet": worker_dotnet},
        )
        if (
            not compose_ok
            or unsafe
            or not worker_declared
            or not api_dotnet
            or not worker_dotnet
        ):
            return False

        self._write_override(config)
        self.cleanup_armed = True

        down = self.harness.compose(
            ["down", "--volumes", "--remove-orphans"], timeout=90
        )
        self.harness.require(down, "Cannot initialize an empty Compose project")
        build = self.harness.compose(
            [
                "build",
                "--pull",
                "--no-cache",
                *sorted(REQUIRED_SERVICES),
            ],
            timeout=self.args.build_timeout,
        )
        build_ok = build.ok
        if not build_ok and self.harness._environment_error(build):
            raise EnvironmentFailure("Docker transport failed during the cold build")
        self.record(
            "cold-build",
            "admission",
            build_ok,
            "docker compose build --pull --no-cache succeeds",
            {"exitCode": build.returncode},
        )
        if not build_ok:
            return False
        digest_after_build = canonical_fixture_digest(self.fixtures)
        self.record(
            "fixture-post-build-integrity",
            "admission",
            digest_after_build == self.fixture_digest,
            self.fixture_digest,
            digest_after_build,
        )
        if digest_after_build != self.fixture_digest:
            return False
        api_image = self.harness.image_id("api")
        worker_a_image = self.harness.image_id("worker-a")
        worker_b_image = self.harness.image_id("worker-b")
        shared = worker_a_image == worker_b_image
        self.record(
            "built-image-contract",
            "admission",
            shared,
            "worker-a and worker-b use one image ID",
            {"api": api_image, "worker": worker_a_image, "workersMatch": shared},
        )
        if not shared:
            return False
        self.baseline_images = {"api": api_image, "worker": worker_a_image}
        up = self.harness.compose(
            [
                "up",
                "-d",
                "--no-build",
                "--force-recreate",
                *sorted(REQUIRED_SERVICES),
            ],
            timeout=600,
        )
        if not up.ok and self.harness._environment_error(up):
            raise EnvironmentFailure("Docker transport failed while starting the stack")
        self.record(
            "stack-start-no-build",
            "admission",
            up.ok,
            "up --no-build succeeds",
            {"exitCode": up.returncode},
        )
        if not up.ok:
            return False
        ready = self.harness.wait_ready(self.args.ready_timeout)
        self.record(
            "health",
            "admission",
            ready,
            "live and ready return HTTP 200",
            {"ready": ready},
        )
        if not ready:
            return False
        worker_security = self.harness.wait_worker_database_security()
        security_ok = (
            worker_security.get("roleVerified") is True
            and worker_security.get("allDmlDenied") is True
            and worker_security.get("executeBoundaryRestricted") is True
        )
        self.record(
            "worker-database-security",
            "admission",
            security_ok,
            "both workers use workflow_worker with only fixed EXECUTE boundaries and no table DML",
            worker_security,
        )
        if not security_ok:
            return False
        after_up = {
            "api": self.harness.image_id("api"),
            "worker": self.harness.image_id("worker-a"),
        }
        self.record(
            "baseline-images",
            "admission",
            after_up == self.baseline_images,
            self.baseline_images,
            after_up,
        )
        return after_up == self.baseline_images

    def _view_count(self, view: str, where: str = "") -> int:
        if view not in AUTOCHECK_VIEWS:
            raise ValueError("Unknown stable view")
        suffix = f" WHERE {where}" if where else ""
        rows = self.harness.psql_rows(
            f"SELECT count(*)::integer AS count FROM autocheck.{view}{suffix}"
        )
        if len(rows) != 1 or not isinstance(rows[0].get("count"), int):
            raise ContractError(f"autocheck.{view} did not return one integer count")
        return int(rows[0]["count"])

    def _view_schema_rows(self) -> list[dict[str, Any]]:
        names = ", ".join(_sql_literal(name) for name in sorted(AUTOCHECK_VIEWS))
        return self.harness.psql_rows(
            "SELECT c.relname AS view_name, c.relkind::text AS relation_kind, "
            "a.attnum::integer AS ordinal, a.attname AS column_name, "
            "pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type "
            "FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid "
            "WHERE n.nspname = 'autocheck' AND c.relname IN ("
            f"{names}) AND a.attnum > 0 AND NOT a.attisdropped "
            "ORDER BY c.relname, a.attnum"
        )

    def _process_rows(self, process_id: str) -> list[dict[str, Any]]:
        return self.harness.psql_rows(
            "SELECT process_id::text, business_key, flow_name, flow_version, state, "
            "current_step_key, created_at, updated_at FROM autocheck.processes "
            f"WHERE process_id = {_sql_literal(process_id)}"
        )

    def _poll_process(
        self, process_id: str, states: set[str], timeout: float = 8
    ) -> dict[str, Any]:
        rows = self.harness.poll_rows(
            "SELECT process_id::text, business_key, flow_name, flow_version, state, "
            "current_step_key, created_at, updated_at FROM autocheck.processes "
            f"WHERE process_id = {_sql_literal(process_id)}",
            lambda values: len(values) == 1 and values[0].get("state") in states,
            timeout=timeout,
        )
        return rows[0]

    def _jobs(self, process_id: str) -> list[dict[str, Any]]:
        return self.harness.psql_rows(
            "SELECT job_id::text, process_id::text, step_instance_id::text, execution_id::text, "
            "state, lease_owner, lease_version, lease_until, attempt_count, next_attempt_at "
            "FROM autocheck.jobs "
            f"WHERE process_id = {_sql_literal(process_id)} ORDER BY job_id"
        )

    def _attempts(self, process_id: str) -> list[dict[str, Any]]:
        return self.harness.psql_rows(
            "SELECT a.attempt_id::text, a.job_id::text, a.execution_id::text, "
            "a.lease_version, a.attempt_number, a.status, a.outcome, a.error_code, "
            "a.started_at, a.finished_at FROM autocheck.attempts a "
            "JOIN autocheck.jobs j ON j.job_id = a.job_id "
            f"WHERE j.process_id = {_sql_literal(process_id)} ORDER BY a.attempt_number"
        )

    def _steps(self, process_id: str) -> list[dict[str, Any]]:
        return self.harness.psql_rows(
            "SELECT step_instance_id::text, process_id::text, step_key, step_type, state, "
            "outcome, entered_at, completed_at FROM autocheck.steps "
            f"WHERE process_id = {_sql_literal(process_id)} ORDER BY entered_at, step_instance_id"
        )

    def _signals(self, process_id: str) -> list[dict[str, Any]]:
        return self.harness.psql_rows(
            "SELECT message_id, process_id::text, signal_type, body_hash, status, received_at "
            "FROM autocheck.signals "
            f"WHERE process_id = {_sql_literal(process_id)} ORDER BY received_at, message_id"
        )

    def _events(self, process_id: str) -> list[dict[str, Any]]:
        return self.harness.psql_rows(
            "SELECT event_id::text, process_id::text, step_instance_id::text, event_type, "
            "occurred_at FROM autocheck.workflow_events "
            f"WHERE process_id = {_sql_literal(process_id)} ORDER BY occurred_at, event_id"
        )

    def _dispatches(self, execution_id: str) -> list[dict[str, Any]]:
        return self.harness.psql_rows(
            "SELECT correlation_id::text, request_id, module, action, version, principal, "
            "payload_hash, status, outcome, occurred_at FROM autocheck.action_dispatches "
            f"WHERE request_id = {_sql_literal(execution_id)} ORDER BY occurred_at, correlation_id"
        )

    def _effects(self, execution_id: str) -> list[dict[str, Any]]:
        return self.harness.effect_rows(
            str(self.fixture["targetSchema"]),
            str(self.fixture["effectTable"]),
            execution_id,
        )

    def _start(
        self,
        label: str,
        mode: str,
        *,
        business_key: str | None = None,
        input_text: str | None = None,
        remember: bool = True,
    ) -> tuple[CommandResult, dict[str, Any] | None, str | None]:
        key = business_key or f"{self.fixture['businessKeys'][mode]}-{label}"
        data_path = (
            "/dev/stdin"
            if input_text is not None
            else f"/autocheck/input/{self.files['processData'][mode]}"
        )
        result, body = self.harness.cli(
            "flow",
            "start",
            self.flow,
            "--business-key",
            key,
            "--data",
            data_path,
            input_text=input_text,
        )
        if not self.harness.ok_envelope(result, body):
            return result, body, None
        process_id = (
            body.get("result", {}).get("processId")
            if isinstance(body.get("result"), dict)
            else None
        )
        try:
            normalized = str(uuid.UUID(str(process_id)))
        except (ValueError, AttributeError):
            return result, body, None
        if normalized != str(process_id).casefold() or normalized == str(
            uuid.UUID(int=0)
        ):
            return result, body, None
        if remember:
            self.processes[label] = normalized
        return result, body, normalized

    def publication(self) -> None:
        commands = [
            self.harness.cli(
                "migration", "apply", "/autocheck/input/migrations", timeout=120
            ),
            self.harness.cli(
                "migration", "apply", "/autocheck/input/migrations", timeout=120
            ),
            self.harness.cli(
                "action", "validate", f"/autocheck/input/{self.files['actionManifest']}"
            ),
            self.harness.cli(
                "action", "publish", f"/autocheck/input/{self.files['actionManifest']}"
            ),
            self.harness.cli(
                "action", "publish", f"/autocheck/input/{self.files['actionManifest']}"
            ),
            self.harness.cli(
                "action",
                "validate",
                f"/autocheck/input/{self.files['disabledActionManifest']}",
            ),
            self.harness.cli(
                "action",
                "publish",
                f"/autocheck/input/{self.files['disabledActionManifest']}",
            ),
            self.harness.cli(
                "action", "activate", f"{self.module}.{self.action}", "--version", "1"
            ),
        ]
        post_migration_security = self.harness.wait_worker_database_security()
        post_migration_security_ok = (
            post_migration_security.get("roleVerified") is True
            and post_migration_security.get("allDmlDenied") is True
            and post_migration_security.get("executeBoundaryRestricted") is True
        )
        self.record(
            "worker-database-security-post-migration",
            "publication",
            post_migration_security_ok,
            "workflow_worker keeps fixed EXECUTE boundaries and no table DML after migration",
            post_migration_security,
        )
        definitions = self.harness.psql_rows(
            "SELECT module, action, version, enabled, is_default FROM autocheck.action_definitions "
            f"WHERE module = {_sql_literal(self.module)} AND action = {_sql_literal(self.action)} "
            "ORDER BY version"
        )
        action_ok = (
            all(self.harness.ok_envelope(result, body) for result, body in commands)
            and post_migration_security_ok
        )
        action_ok = action_ok and definitions == [
            {
                "module": self.module,
                "action": self.action,
                "version": 1,
                "enabled": True,
                "is_default": True,
            },
            {
                "module": self.module,
                "action": self.action,
                "version": 2,
                "enabled": False,
                "is_default": False,
            },
        ]
        self.record(
            "migration-and-action-publication",
            "publication",
            action_ok,
            "repeatable migration and v1/v2 action publication through CLI",
            {
                "commands": [self._command_view(*item) for item in commands],
                "definitions": definitions,
            },
        )
        if not action_ok:
            raise ContractError("Migration or action publication prerequisite failed")

        valid_paths = (self.files["flowV1Json"], self.files["flowV1Yaml"])
        valid_results = [
            self.harness.cli("flow", "validate", f"/autocheck/input/{path}")
            for path in valid_paths
        ]
        invalid_paths = [
            *self.files["invalidMaps"]["schema"],
            *self.files["invalidMaps"]["semantic"],
        ]
        invalid_validation = [
            self.harness.cli("flow", "validate", f"/autocheck/input/{path}")
            for path in invalid_paths
        ]
        before = self._view_count("flow_versions")
        invalid_publication = [
            self.harness.cli("flow", "publish", f"/autocheck/input/{path}")
            for path in invalid_paths
        ]
        after = self._view_count("flow_versions")
        publish = self.harness.cli(
            "flow", "publish", f"/autocheck/input/{self.files['flowV1Json']}"
        )
        repeat = self.harness.cli(
            "flow", "publish", f"/autocheck/input/{self.files['flowV1Yaml']}"
        )
        source = json.loads(
            (self.fixtures / self.files["flowV1Json"]).read_text(encoding="utf-8")
        )
        source["steps"][0]["task"]["timeout_ms"] -= 1
        conflict = self.harness.cli(
            "flow", "publish", "/dev/stdin", input_text=json.dumps(source)
        )
        activate = self.harness.cli("flow", "activate", self.flow, "--version", "1")
        version_rows = self.harness.psql_rows(
            "SELECT flow_name, flow_version, status, is_active, published_at "
            "FROM autocheck.flow_versions "
            f"WHERE flow_name = {_sql_literal(self.flow)} ORDER BY flow_version"
        )
        map_ok = (
            all(self.harness.ok_envelope(*item) for item in valid_results)
            and all(
                self.harness.error_envelope(result, body)
                for result, body in invalid_validation
            )
            and all(
                self.harness.error_envelope(result, body)
                for result, body in invalid_publication
            )
            and before == after
            and self.harness.ok_envelope(*publish)
            and self.harness.ok_envelope(*repeat)
            and self.harness.error_envelope(*conflict)
            and self.harness.ok_envelope(*activate)
            and len(version_rows) == 1
            and version_rows[0].get("flow_version") == 1
            and version_rows[0].get("is_active") is True
        )
        self.record(
            "map-validation-and-publication",
            "publication",
            map_ok,
            "valid JSON/YAML accepted; every invalid map rejected without side effects",
            {
                "invalidMapCount": len(invalid_paths),
                "invalidValidateRejected": sum(
                    not result.ok for result, _ in invalid_validation
                ),
                "invalidPublishRejected": sum(
                    not result.ok for result, _ in invalid_publication
                ),
                "countBefore": before,
                "countAfter": after,
                "versionRows": version_rows,
            },
        )
        if not map_ok:
            raise ContractError(
                "Workflow map validation/publication prerequisite failed"
            )
        current = {
            "api": self.harness.image_id("api"),
            "worker": self.harness.image_id("worker-a"),
        }
        unchanged = (
            current == self.baseline_images
            and self.harness.image_id("worker-b") == current["worker"]
        )
        self.record(
            "publication-image-immutability",
            "publication",
            unchanged,
            self.baseline_images,
            current,
        )

    def execution(self) -> None:
        start, body, process_id = self._start("signal", "signal")
        if process_id is None:
            raise ContractError(
                f"Signal-route process did not start: {self._command_view(start, body)}"
            )
        waiting = self._poll_process(process_id, {"WAITING_SIGNAL"})
        jobs = self._jobs(process_id)
        attempts = self._attempts(process_id)
        execution_id = str(jobs[0].get("execution_id")) if len(jobs) == 1 else ""
        dispatches = self._dispatches(execution_id) if execution_id else []
        effects = self._effects(execution_id) if execution_id else []
        flow_get = self.harness.cli("flow", "get", process_id)
        flow_get_result = (
            flow_get[1].get("result")
            if self.harness.ok_envelope(*flow_get)
            and isinstance(flow_get[1].get("result"), dict)
            else {}
        )
        flow_get_ok = (
            flow_get_result.get("resource") == "process"
            and flow_get_result.get("processId") == process_id
            and flow_get_result.get("flowName") == self.flow
            and flow_get_result.get("flowVersion") == 1
            and flow_get_result.get("state") == "WAITING_SIGNAL"
            and flow_get_result.get("currentStepKey") == self.fixture["steps"]["wait"]
        )
        workflow_get = self.harness.post_action(
            "workflow", "get", {"processId": process_id}, ("workflow:read",)
        )
        workflow_result = (
            workflow_get.body.get("result")
            if workflow_get.status == 200
            and isinstance(workflow_get.body, dict)
            and workflow_get.body.get("status") == "ok"
            and isinstance(workflow_get.body.get("result"), dict)
            else {}
        )
        workflow_get_ok = (
            isinstance(workflow_result.get("process"), dict)
            and workflow_result["process"].get("processId") == process_id
            and all(
                isinstance(workflow_result.get(name), list)
                for name in ("steps", "jobs", "attempts")
            )
        )
        automatic_ok = (
            process_state_matches(
                waiting, "WAITING_SIGNAL", str(self.fixture["steps"]["wait"])
            )
            and len(jobs) == 1
            and job_attempts_consistent(
                jobs[0], attempts, str(self.fixture["outcomes"]["signal"])
            )
            and len(dispatches) == 1
            and action_dispatch_matches(
                dispatches[0],
                execution_id=execution_id,
                module=self.module,
                action=self.action,
                outcome=str(self.fixture["outcomes"]["signal"]),
            )
            and len(effects) == 1
            and effects[0].get("business_value")
            == self.fixture["businessValues"]["signal"]
            and flow_get_ok
            and workflow_get_ok
        )

        signals_before = self._signals(process_id)
        events_before = self._events(process_id)
        signal_args = (
            "flow",
            "signal",
            process_id,
            "--type",
            str(self.fixture["signalType"]),
            "--message-id",
            str(self.fixture["signalMessageId"]),
            "--payload",
        )
        accepted = self.harness.cli(
            *signal_args, f"/autocheck/input/{self.files['signalData']}"
        )
        completed = self._poll_process(process_id, {"COMPLETED"})
        signals_accepted = self._signals(process_id)
        events_accepted = self._events(process_id)
        duplicate = self.harness.cli(
            *signal_args, f"/autocheck/input/{self.files['signalData']}"
        )
        signals_duplicate = self._signals(process_id)
        events_duplicate = self._events(process_id)
        signal_data = json.loads(
            (self.fixtures / self.files["signalData"]).read_text(encoding="utf-8")
        )
        if not isinstance(signal_data, dict) or len(signal_data) != 1:
            raise FixtureError("Signal fixture must contain exactly one property")
        signal_key = next(iter(signal_data))
        changed_signal = {signal_key: str(signal_data[signal_key]) + "-changed"}
        conflict = self.harness.cli(
            *signal_args, "/dev/stdin", input_text=json.dumps(changed_signal)
        )
        signals_conflict = self._signals(process_id)
        events_conflict = self._events(process_id)
        steps = self._steps(process_id)
        accepted_status = (
            accepted[1].get("result", {}).get("status")
            if self.harness.ok_envelope(*accepted)
            else None
        )
        duplicate_status = (
            duplicate[1].get("result", {}).get("status")
            if self.harness.ok_envelope(*duplicate)
            else None
        )
        end_ok = any(
            row.get("step_key") == self.fixture["steps"]["end"]
            and row.get("step_type") == "END"
            and row.get("state") == "COMPLETED"
            and row.get("outcome") == self.fixture["outcomes"]["completed"]
            for row in steps
        )
        self.record(
            "automatic-signal-end",
            "execution",
            automatic_ok
            and process_state_matches(
                completed, "COMPLETED", str(self.fixture["steps"]["end"])
            )
            and end_ok,
            "automatic -> wait_signal -> end with one action effect",
            {
                "automatic": automatic_ok,
                "finalState": completed.get("state"),
                "endStep": end_ok,
                "flowGet": flow_get_ok,
                "workflowGet": workflow_get_ok,
            },
        )
        old_events = {row.get("event_id"): row for row in events_before}
        accepted_events = {row.get("event_id"): row for row in events_accepted}
        history_ok = (
            signals_before == []
            and len(signals_accepted) == 1
            and signals_duplicate == signals_accepted
            and signals_conflict == signals_accepted
            and len(events_accepted) > len(events_before)
            and all(accepted_events.get(key) == row for key, row in old_events.items())
            and events_duplicate == events_accepted
            and events_conflict == events_accepted
        )
        signal_ok = (
            accepted_status == "accepted"
            and duplicate_status == "duplicate"
            and self.harness.error_envelope(*conflict)
            and "conflict" in str(self.harness.error_code(conflict[1]))
            and history_ok
        )

        stopped = self.harness.compose(["stop", "worker-a", "worker-b"], timeout=30)
        self.harness.require(stopped, "Cannot stop workers for the early-signal probe")
        early_start, early_body, early_id = self._start(
            "early-signal", "signal", remember=False
        )
        if early_id is None:
            restored = self.harness.compose(
                ["up", "-d", "--no-build", "worker-a", "worker-b"], timeout=40
            )
            self.harness.require(
                restored, "Cannot restore workers after early-signal setup"
            )
            raise ContractError(
                f"Early-signal process did not start: {self._command_view(early_start, early_body)}"
            )
        early_message_id = f"{self.fixture['signalMessageId']}-early"
        early_args = (
            "flow",
            "signal",
            early_id,
            "--type",
            str(self.fixture["signalType"]),
            "--message-id",
            early_message_id,
            "--payload",
        )
        early_accepted = self.harness.cli(
            *early_args, f"/autocheck/input/{self.files['signalData']}"
        )
        early_before_resume = self._signals(early_id)
        restarted = self.harness.compose(
            ["up", "-d", "--no-build", "worker-a", "worker-b"], timeout=40
        )
        self.harness.require(restarted, "Cannot restart workers for the early signal")
        early_completed = self._poll_process(early_id, {"COMPLETED"}, timeout=8)
        early_after_resume = self._signals(early_id)
        global_conflict = self.harness.cli(
            "flow",
            "signal",
            process_id,
            "--type",
            str(self.fixture["signalType"]),
            "--message-id",
            early_message_id,
            "--payload",
            f"/autocheck/input/{self.files['signalData']}",
        )
        early_after_conflict = self._signals(early_id)
        original_after_conflict = self._signals(process_id)
        early_status = (
            early_accepted[1].get("result", {}).get("status")
            if self.harness.ok_envelope(*early_accepted)
            else None
        )
        early_ok = (
            early_status == "accepted"
            and len(early_before_resume) == 1
            and early_before_resume[0].get("status") == "ACCEPTED"
            and process_state_matches(
                early_completed, "COMPLETED", str(self.fixture["steps"]["end"])
            )
            and len(early_after_resume) == 1
            and early_after_resume[0].get("status") == "APPLIED"
            and self.harness.error_envelope(*global_conflict)
            and "conflict" in str(self.harness.error_code(global_conflict[1]))
            and early_after_conflict == early_after_resume
            and original_after_conflict == signals_conflict
        )
        self.record(
            "signal-idempotency-and-history",
            "execution",
            signal_ok and early_ok,
            "accepted, duplicate, global conflict and early delivery reconciliation",
            {
                "accepted": accepted_status,
                "duplicate": duplicate_status,
                "conflictCode": self.harness.error_code(conflict[1]),
                "signalCounts": [
                    len(signals_before),
                    len(signals_accepted),
                    len(signals_duplicate),
                    len(signals_conflict),
                ],
                "eventCounts": [
                    len(events_before),
                    len(events_accepted),
                    len(events_duplicate),
                    len(events_conflict),
                ],
                "earlyAccepted": early_status,
                "earlyFinalState": early_completed.get("state"),
                "earlySignalState": (
                    early_after_resume[0].get("status")
                    if len(early_after_resume) == 1
                    else None
                ),
                "crossProcessConflictCode": self.harness.error_code(global_conflict[1]),
            },
        )

        manual_start, manual_body, manual_id = self._start("manual", "manual")
        if manual_id is None:
            raise ContractError(
                f"Manual-route process did not start: {self._command_view(manual_start, manual_body)}"
            )
        manual = self._poll_process(manual_id, {"WAITING_MANUAL"})
        manual_steps = self._steps(manual_id)
        manual_ok = process_state_matches(
            manual, "WAITING_MANUAL", str(self.fixture["steps"]["manual"])
        ) and any(
            row.get("step_key") == self.fixture["steps"]["manual"]
            and row.get("step_type") == "MANUAL"
            and row.get("state") == "WAITING"
            for row in manual_steps
        )
        self.record(
            "manual-wait",
            "execution",
            manual_ok,
            "persistent WAITING_MANUAL",
            {"process": manual, "stepCount": len(manual_steps)},
        )

        view_counts: dict[str, int | str] = {}
        for view in sorted(AUTOCHECK_VIEWS):
            try:
                view_counts[view] = self._view_count(view)
            except ContractError:
                view_counts[view] = "unavailable"
        schema_rows = self._view_schema_rows()
        schemas_match = stable_view_schemas_match(schema_rows)
        stable = (
            all(isinstance(value, int) for value in view_counts.values())
            and schemas_match
        )
        self.record(
            "stable-views",
            "execution",
            stable,
            {"views": sorted(AUTOCHECK_VIEWS), "exactSchemas": True},
            {"counts": view_counts, "exactSchemas": schemas_match},
        )

    def versioning(self) -> None:
        publish = self.harness.cli(
            "flow", "publish", f"/autocheck/input/{self.files['flowV2Json']}"
        )
        activate = self.harness.cli("flow", "activate", self.flow, "--version", "2")
        if not self.harness.ok_envelope(*publish) or not self.harness.ok_envelope(
            *activate
        ):
            raise ContractError("Flow v2 could not be published and activated")
        rows = self.harness.psql_rows(
            "SELECT flow_name, flow_version, status, is_active, published_at "
            "FROM autocheck.flow_versions "
            f"WHERE flow_name = {_sql_literal(self.flow)} ORDER BY flow_version"
        )
        start, body, process_id = self._start(
            "v2", "signal", business_key=str(self.fixture["businessKeys"]["v2"])
        )
        if process_id is None:
            raise ContractError(
                f"Flow v2 process did not start: {self._command_view(start, body)}"
            )
        new_process = self._poll_process(process_id, {"WAITING_MANUAL"})
        old_id = self.processes.get("manual") or self.processes.get("signal")
        old_rows = self._process_rows(str(old_id)) if old_id else []
        same = self._start(
            "v2-repeat",
            "signal",
            business_key=str(self.fixture["businessKeys"]["v2"]),
            remember=False,
        )
        changed_data = (self.fixtures / self.files["processData"]["changed"]).read_text(
            encoding="utf-8"
        )
        changed = self._start(
            "v2-conflict",
            "signal",
            business_key=str(self.fixture["businessKeys"]["v2"]),
            input_text=changed_data,
            remember=False,
        )
        jobs = self._jobs(process_id)
        execution_id = str(jobs[0].get("execution_id")) if len(jobs) == 1 else ""
        dispatches = self._dispatches(execution_id) if execution_id else []
        effects = self._effects(execution_id) if execution_id else []
        valid = (
            exact_active_version(rows, 2)
            and len(old_rows) == 1
            and old_rows[0].get("flow_version") == 1
            and new_process.get("flow_version") == 2
            and process_state_matches(
                new_process, "WAITING_MANUAL", str(self.fixture["steps"]["manual"])
            )
            and same[2] == process_id
            and self.harness.error_envelope(changed[0], changed[1])
            and "conflict" in str(self.harness.error_code(changed[1]))
            and len(dispatches) == 1
            and action_dispatch_matches(
                dispatches[0],
                execution_id=execution_id,
                module=self.module,
                action=self.action,
                outcome=str(self.fixture["outcomes"]["signal"]),
            )
            and len(effects) == 1
            and effects[0].get("business_value")
            == self.fixture["businessValues"]["signal"]
        )
        self.record(
            "version-pinning-and-start-idempotency",
            "versioning",
            valid,
            "old=v1, new=v2, action=v1, same start replays, changed data conflicts",
            {
                "oldVersion": old_rows[0].get("flow_version") if old_rows else None,
                "newVersion": new_process.get("flow_version"),
                "sameProcess": same[2] == process_id,
                "changedCode": self.harness.error_code(changed[1]),
                "actionVersions": [row.get("version") for row in dispatches],
                "activeVersions": [
                    row.get("flow_version")
                    for row in rows
                    if row.get("is_active") is True
                ],
            },
        )

        unknown_start, unknown_body, unknown_id = self._start("unknown", "unknown")
        if unknown_id is None:
            raise ContractError(
                f"Unknown-outcome process did not start: {self._command_view(unknown_start, unknown_body)}"
            )
        unknown_process = self._poll_process(unknown_id, {"FAILED"})
        unknown_jobs = self._jobs(unknown_id)
        unknown_attempts = self._attempts(unknown_id)
        unknown_execution = (
            str(unknown_jobs[0].get("execution_id")) if len(unknown_jobs) == 1 else ""
        )
        if not terminal_failure_consistent(
            unknown_process,
            unknown_jobs,
            unknown_attempts,
            self._effects(unknown_execution) if unknown_execution else [],
            expected_attempts=1,
        ):
            unknown_terminal = False
        else:
            unknown_terminal = True
        for item in self.checks:
            if item["name"] == "version-pinning-and-start-idempotency":
                if isinstance(item.get("actual"), dict):
                    item["actual"]["unknownOutcomeTerminal"] = unknown_terminal
                if not unknown_terminal:
                    item["status"] = "failed"
                break

    def _snapshot(self, process_id: str, execution_id: str) -> dict[str, Any]:
        return {
            "counts": {
                view: self._view_count(view) for view in sorted(AUTOCHECK_VIEWS)
            },
            "processes": self._process_rows(process_id),
            "steps": self._steps(process_id),
            "jobs": self._jobs(process_id),
            "attempts": self._attempts(process_id),
            "signals": self._signals(process_id),
            "events": self._events(process_id),
            "dispatches": self._dispatches(execution_id),
            "effects": self._effects(execution_id),
        }

    def concurrency(self) -> None:
        activate = self.harness.cli("flow", "activate", self.flow, "--version", "1")
        if not self.harness.ok_envelope(*activate):
            raise ContractError(
                "Flow v1 could not be activated for the concurrency scenario"
            )
        stopped = self.harness.compose(["stop", "worker-a", "worker-b"], timeout=30)
        self.harness.require(
            stopped, "Cannot stop workers for the deterministic claim scenario"
        )
        before_dispatch = self._view_count(
            "action_dispatches",
            f"module = {_sql_literal(self.module)} AND action = {_sql_literal(self.action)}",
        )
        start, body, process_id = self._start("concurrent", "signal")
        if process_id is None:
            raise ContractError(
                f"Concurrency process did not start: {self._command_view(start, body)}"
            )
        queued = self._jobs(process_id)
        if len(queued) != 1 or queued[0].get("state") != "READY":
            raise ContractError(
                "The stopped workers did not leave one logical READY job"
            )
        created = self.harness.compose(
            ["create", "--no-build", "--force-recreate", "worker-a", "worker-b"],
            timeout=40,
            failpoint="after_job_claim",
        )
        self.harness.require(created, "Cannot create both workers with after_job_claim")
        container_ids = self.harness.service_container_ids(
            ("worker-a", "worker-b"), include_stopped=True
        )
        postgres_id = self.harness.service_container_ids(("postgres",))["postgres"]
        started = self.harness.run(
            ["docker", "start", container_ids["worker-a"], container_ids["worker-b"]],
            timeout=20,
            failpoint="after_job_claim",
        )
        self.harness.require(started, "Cannot start both workers with after_job_claim")
        initial_claim_row = self.harness.poll_rows(
            "SELECT job_id::text, process_id::text, execution_id::text, state, "
            "lease_owner, lease_version, attempt_count FROM autocheck.jobs "
            f"WHERE process_id = {_sql_literal(process_id)}",
            lambda rows: (
                len(rows) == 1
                and rows[0].get("state") == "LEASED"
                and rows[0].get("lease_owner") in {"worker-a", "worker-b"}
                and rows[0].get("attempt_count") == 1
            ),
            timeout=8,
            container_id=postgres_id,
        )[0]
        winner = str(initial_claim_row["lease_owner"])
        loser = "worker-b" if winner == "worker-a" else "worker-a"
        winner_ack = self.harness.wait_failpoint(
            winner,
            "after_job_claim",
            container_id=container_ids[winner],
        )
        killed = self.harness.run(["docker", "kill", container_ids[winner]], timeout=20)
        self.harness.require(killed, "Cannot kill the acknowledged claim winner")
        loser_ack = self.harness.wait_failpoint(loser, "after_job_claim", timeout=8)
        reclaimed = self.harness.poll_rows(
            "SELECT job_id::text, process_id::text, execution_id::text, state, lease_owner, "
            "lease_version, attempt_count FROM autocheck.jobs "
            f"WHERE process_id = {_sql_literal(process_id)}",
            lambda rows: (
                len(rows) == 1
                and rows[0].get("state") == "LEASED"
                and rows[0].get("lease_owner") == loser
                and rows[0].get("attempt_count") == 2
            ),
            timeout=8,
        )[0]
        reclaimed_attempts = self._attempts(process_id)
        first_attempt = reclaimed_attempts[0] if reclaimed_attempts else {}
        initial_lease = first_attempt.get("lease_version")
        initial_claim = (
            len(reclaimed_attempts) == 2
            and first_attempt.get("attempt_number") == 1
            and first_attempt.get("status") == "STALE"
            and strictly_increasing_integer(
                reclaimed.get("lease_version"), initial_lease
            )
        )
        reclaimed_ok = (
            reclaimed.get("attempt_count") == 2
            and len(reclaimed_attempts) == 2
            and len({row.get("attempt_id") for row in reclaimed_attempts}) == 2
            and reclaimed_attempts[-1].get("attempt_number") == 2
            and reclaimed_attempts[-1].get("lease_version")
            == reclaimed.get("lease_version")
            and reclaimed_attempts[-1].get("status") == "RUNNING"
        )
        execution_id = str(reclaimed["execution_id"])
        before_stale = self._snapshot(process_id, execution_id)
        stale = self.harness.cli(
            "flow",
            "test-finish",
            str(reclaimed["job_id"]),
            "--owner",
            winner,
            "--lease-version",
            str(initial_lease),
            "--outcome",
            str(self.fixture["outcomes"]["signal"]),
            "--result",
            f"/autocheck/input/{self.files['resultData']}",
        )
        after_stale = self._snapshot(process_id, execution_id)
        stale_ok = (
            self.harness.error_envelope(*stale)
            and self.harness.error_code(stale[1]) == "workflow.lease_stale"
            and before_stale == after_stale
        )
        killed_loser = self.harness.compose(["kill", loser], timeout=20)
        self.harness.require(
            killed_loser, "Cannot stop the reclaiming failpoint worker"
        )
        restart = self.harness.compose(
            ["up", "-d", "--no-build", "--force-recreate", loser], timeout=40
        )
        self.harness.require(
            restart, "Cannot restart the reclaiming worker without a failpoint"
        )
        self._poll_process(process_id, {"WAITING_SIGNAL"}, timeout=8)
        final_jobs = self._jobs(process_id)
        attempts = self._attempts(process_id)
        effects = self._effects(execution_id)
        after_dispatch = self._view_count(
            "action_dispatches",
            f"module = {_sql_literal(self.module)} AND action = {_sql_literal(self.action)}",
        )
        valid = (
            initial_claim
            and reclaimed_ok
            and winner_ack.get("instanceId") == winner
            and loser_ack.get("instanceId") == loser
            and reclaimed.get("job_id") == queued[0].get("job_id")
            and reclaimed.get("execution_id") == queued[0].get("execution_id")
            and stale_ok
            and len(final_jobs) == 1
            and final_jobs[0].get("state") == "SUCCEEDED"
            and final_jobs[0].get("job_id") == reclaimed.get("job_id")
            and final_jobs[0].get("execution_id") == execution_id
            and strictly_increasing_integer(
                final_jobs[0].get("lease_version"), reclaimed.get("lease_version")
            )
            and len(attempts) >= 3
            and len({row.get("attempt_id") for row in attempts}) == len(attempts)
            and all(
                row.get("job_id") == reclaimed.get("job_id")
                and row.get("execution_id") == execution_id
                for row in attempts
            )
            and sum(row.get("status") == "SUCCEEDED" for row in attempts) == 1
            and after_dispatch - before_dispatch == 1
            and len(effects) == 1
        )
        self.record(
            "two-worker-reclaim-and-stale-finish",
            "concurrency",
            valid,
            "one winner, same job/execution reclaim, stale finish rejected, one effect",
            {
                "winner": winner,
                "loser": loser,
                "initialClaim": initial_claim,
                "reclaimedAttempt": reclaimed_ok,
                "sameJob": reclaimed.get("job_id") == queued[0].get("job_id"),
                "sameExecution": reclaimed.get("execution_id")
                == queued[0].get("execution_id"),
                "leaseVersions": [
                    initial_lease,
                    reclaimed.get("lease_version"),
                    final_jobs[0].get("lease_version") if final_jobs else None,
                ],
                "staleCode": self.harness.error_code(stale[1]),
                "staleSnapshotUnchanged": before_stale == after_stale,
                "attemptCount": len(attempts),
                "dispatchDelta": after_dispatch - before_dispatch,
                "effectCount": len(effects),
            },
        )
        normal = self.harness.compose(
            ["up", "-d", "--no-build", "--force-recreate", "worker-a", "worker-b"],
            timeout=40,
        )
        self.harness.require(
            normal, "Cannot restore both workers after the concurrency scenario"
        )

    def recovery(self) -> None:
        stopped = self.harness.compose(["stop", "worker-a", "worker-b"], timeout=30)
        self.harness.require(stopped, "Cannot stop workers for the rollback scenario")
        before_dispatch = self._view_count(
            "action_dispatches",
            f"module = {_sql_literal(self.module)} AND action = {_sql_literal(self.action)}",
        )
        start, body, process_id = self._start("atomic", "signal")
        if process_id is None:
            raise ContractError(
                f"Rollback process did not start: {self._command_view(start, body)}"
            )
        up = self.harness.compose(
            ["up", "-d", "--no-build", "--force-recreate", "worker-a"],
            timeout=40,
            failpoint="after_action_before_finish",
        )
        self.harness.require(
            up, "Cannot start worker-a with after_action_before_finish"
        )
        ack = self.harness.wait_failpoint("worker-a", "after_action_before_finish")
        held_jobs = self._jobs(process_id)
        if len(held_jobs) != 1:
            raise ContractError("Rollback scenario did not expose one held job")
        held = held_jobs[0]
        killed = self.harness.compose(["kill", "worker-a"], timeout=20)
        self.harness.require(
            killed, "Cannot kill worker-a at the action/finish boundary"
        )
        effects_at_crash = self._effects(str(held["execution_id"]))
        dispatch_at_crash = self._view_count(
            "action_dispatches",
            f"module = {_sql_literal(self.module)} AND action = {_sql_literal(self.action)}",
        )
        restart = self.harness.compose(
            ["up", "-d", "--no-build", "--force-recreate", "worker-b"], timeout=40
        )
        self.harness.require(restart, "Cannot start worker-b for rollback recovery")
        self._poll_process(process_id, {"WAITING_SIGNAL"}, timeout=8)
        final_jobs = self._jobs(process_id)
        final_effects = self._effects(str(held["execution_id"]))
        final_dispatch = self._view_count(
            "action_dispatches",
            f"module = {_sql_literal(self.module)} AND action = {_sql_literal(self.action)}",
        )
        valid = (
            ack.get("instanceId") == "worker-a"
            and not effects_at_crash
            and dispatch_at_crash == before_dispatch
            and len(final_effects) == 1
            and final_dispatch - before_dispatch == 1
            and len(final_jobs) == 1
            and final_jobs[0].get("state") == "SUCCEEDED"
            and final_jobs[0].get("job_id") == held.get("job_id")
            and final_jobs[0].get("execution_id") == held.get("execution_id")
        )
        self.record(
            "action-finish-rollback-and-recovery",
            "recovery",
            valid,
            "zero partial effects at crash and one committed effect after recovery",
            {
                "effectAtCrash": len(effects_at_crash),
                "dispatchAtCrash": dispatch_at_crash - before_dispatch,
                "effectAfterRecovery": len(final_effects),
                "dispatchAfterRecovery": final_dispatch - before_dispatch,
                "sameJob": len(final_jobs) == 1
                and final_jobs[0].get("job_id") == held.get("job_id"),
            },
        )
        normal = self.harness.compose(
            ["up", "-d", "--no-build", "--force-recreate", "worker-a", "worker-b"],
            timeout=40,
        )
        self.harness.require(
            normal, "Cannot restore both workers after rollback recovery"
        )

    def _terminal_probe(
        self, label: str, mode: str, expected_error: str | None
    ) -> dict[str, Any]:
        start, body, process_id = self._start(label, mode)
        if process_id is None:
            return {"valid": False, "start": self._command_view(start, body)}
        process = self._poll_process(process_id, {"FAILED"}, timeout=8)
        jobs = self._jobs(process_id)
        attempts = self._attempts(process_id)
        execution_id = str(jobs[0].get("execution_id")) if len(jobs) == 1 else ""
        effects = self._effects(execution_id) if execution_id else []
        return {
            "valid": terminal_failure_consistent(
                process,
                jobs,
                attempts,
                effects,
                expected_attempts=1,
                expected_error=expected_error,
            ),
            "processState": process.get("state"),
            "jobState": jobs[0].get("state") if jobs else None,
            "attemptCount": len(attempts),
            "errorCodes": [row.get("error_code") for row in attempts],
            "effectCount": len(effects),
        }

    def resilience(self) -> None:
        activate = self.harness.cli("flow", "activate", self.flow, "--version", "1")
        if not self.harness.ok_envelope(*activate):
            raise ContractError("Flow v1 could not be activated for persistence checks")
        _, _, wait_id = self._start("wait-persistence", "signal")
        if wait_id is None:
            raise ContractError("WAITING_SIGNAL persistence process did not start")
        self._poll_process(wait_id, {"WAITING_SIGNAL"})
        waiting_ids = [item for item in (self.processes.get("manual"), wait_id) if item]
        waiting_before = {
            process_id: self._process_rows(process_id)[0] for process_id in waiting_ids
        }
        stopped = self.harness.compose(["stop", "worker-a", "worker-b"], timeout=30)
        self.harness.require(
            stopped, "Cannot stop workers before the READY persistence probe"
        )
        _, _, ready_id = self._start("ready-persistence", "signal")
        if ready_id is None:
            raise ContractError("READY persistence process did not start")
        ready_before = self._jobs(ready_id)
        if len(ready_before) != 1 or ready_before[0].get("state") != "READY":
            raise ContractError("Stopped workers did not leave one READY job")
        recreated = self.harness.compose(
            ["up", "-d", "--no-build", "--force-recreate", "worker-a", "worker-b"],
            timeout=40,
        )
        self.harness.require(
            recreated, "Cannot recreate workers for the READY persistence probe"
        )
        self._poll_process(ready_id, {"WAITING_SIGNAL"}, timeout=8)
        ready_after = self._jobs(ready_id)
        ready_preserved = (
            len(ready_after) == 1
            and ready_after[0].get("job_id") == ready_before[0].get("job_id")
            and ready_after[0].get("execution_id")
            == ready_before[0].get("execution_id")
            and ready_after[0].get("state") == "SUCCEEDED"
        )

        _, _, retry_id = self._start("retry", "retry")
        if retry_id is None:
            raise ContractError("Retry process did not start")
        retry_wait = self.harness.poll_rows(
            "SELECT job_id::text, process_id::text, execution_id::text, state, lease_version, "
            "attempt_count, next_attempt_at FROM autocheck.jobs "
            f"WHERE process_id = {_sql_literal(retry_id)}",
            lambda rows: len(rows) == 1 and rows[0].get("state") == "RETRY_WAIT",
            timeout=3,
            interval=0.02,
        )[0]
        retry_recreate = self.harness.compose(
            ["up", "-d", "--no-build", "--force-recreate", "worker-a", "worker-b"],
            timeout=40,
        )
        self.harness.require(
            retry_recreate, "Cannot recreate workers during RETRY_WAIT"
        )
        retry_process = self._poll_process(retry_id, {"FAILED"}, timeout=8)
        retry_jobs = self._jobs(retry_id)
        retry_attempts = self._attempts(retry_id)
        retry_execution = (
            str(retry_jobs[0].get("execution_id")) if len(retry_jobs) == 1 else ""
        )
        retry_effects = self._effects(retry_execution) if retry_execution else []
        retry_events = self._events(retry_id)
        retry_valid = (
            terminal_failure_consistent(
                retry_process,
                retry_jobs,
                retry_attempts,
                retry_effects,
                expected_attempts=3,
                expected_error=str(self.fixture["errorCodes"]["retry"]),
            )
            and [row.get("attempt_number") for row in retry_attempts] == [1, 2, 3]
            and len({row.get("attempt_id") for row in retry_attempts}) == 3
            and len({row.get("job_id") for row in retry_attempts}) == 1
            and len({row.get("execution_id") for row in retry_attempts}) == 1
            and any(row.get("event_type") == "TaskFailed" for row in retry_events)
        )
        error_probe = self._terminal_probe(
            "non-retryable-error", "error", str(self.fixture["errorCodes"]["error"])
        )
        invalid_probe = self._terminal_probe("invalid-result", "invalid", None)
        failures_ok = retry_valid and error_probe["valid"] and invalid_probe["valid"]
        self.record(
            "bounded-retry-and-terminal-failures",
            "resilience",
            failures_ok,
            "three bounded retry attempts; non-retryable and invalid result fail once; no effects",
            {
                "retryAttemptCount": len(retry_attempts),
                "retryErrorCodes": [row.get("error_code") for row in retry_attempts],
                "taskFailedEvent": any(
                    row.get("event_type") == "TaskFailed" for row in retry_events
                ),
                "nonRetryable": error_probe,
                "invalidResult": invalid_probe,
            },
        )
        waiting_preserved = True
        for process_id, row in waiting_before.items():
            current = self._process_rows(process_id)
            waiting_preserved = (
                waiting_preserved
                and len(current) == 1
                and all(
                    current[0].get(field) == row.get(field)
                    for field in (
                        "process_id",
                        "flow_name",
                        "flow_version",
                        "state",
                        "current_step_key",
                    )
                )
            )
        retry_identity = (
            len(retry_jobs) == 1
            and retry_jobs[0].get("job_id") == retry_wait.get("job_id")
            and retry_jobs[0].get("execution_id") == retry_wait.get("execution_id")
        )
        persistence_ok = ready_preserved and retry_identity and waiting_preserved
        self.record(
            "worker-recreate-persistence",
            "resilience",
            persistence_ok,
            "READY, RETRY_WAIT, WAITING_SIGNAL and WAITING_MANUAL survive no-build recreation",
            {
                "readyIdentityPreserved": ready_preserved,
                "retryIdentityPreserved": retry_identity,
                "waitingStatesPreserved": waiting_preserved,
            },
        )

    def integrity(self) -> None:
        current = {
            "api": self.harness.image_id("api"),
            "worker": self.harness.image_id("worker-a"),
        }
        worker_b = self.harness.image_id("worker-b")
        fixture_digest = canonical_fixture_digest(self.fixtures)
        worker_security = self.harness.wait_worker_database_security()
        worker_security_ok = (
            worker_security.get("roleVerified") is True
            and worker_security.get("allDmlDenied") is True
            and worker_security.get("executeBoundaryRestricted") is True
        )
        valid = (
            current == self.baseline_images
            and worker_b == current["worker"]
            and fixture_digest == self.fixture_digest
            and worker_security_ok
        )
        self.record(
            "runtime-image-immutability",
            "integrity",
            valid,
            self.baseline_images,
            {
                **current,
                "workerB": worker_b,
                "fixtureDigestUnchanged": fixture_digest == self.fixture_digest,
                "workerDatabaseSecurity": worker_security_ok,
            },
        )

    def run_checks(self) -> None:
        admitted = self.admission()
        if not admitted:
            for phase in PHASE_CHECKS:
                self.fail_missing(phase, "Admission prerequisite failed")
            return
        self.run_phase("publication", self.publication)
        if any(
            item["name"] in PHASE_CHECKS["publication"] and item["status"] == "failed"
            for item in self.checks
        ):
            for phase in (
                "execution",
                "versioning",
                "concurrency",
                "recovery",
                "resilience",
            ):
                self.fail_missing(phase, "Publication prerequisite failed")
        else:
            self.run_phase("execution", self.execution)
            self.run_phase("versioning", self.versioning)
            self.run_phase("concurrency", self.concurrency)
            self.run_phase("recovery", self.recovery)
            self.run_phase("resilience", self.resilience)
        self.run_phase("integrity", self.integrity)

    def cleanup(self) -> str | None:
        if self.args.keep_stack or not self.cleanup_armed:
            return None
        result = self.harness.compose(
            ["down", "--volumes", "--remove-orphans", "--rmi", "local"],
            timeout=120,
        )
        images_removed = True
        for tag in self.created_image_tags:
            image_result = self.harness.run(["docker", "image", "rm", tag], timeout=120)
            missing = (
                "no such image"
                in (image_result.stdout + "\n" + image_result.stderr).casefold()
            )
            images_removed = images_removed and (image_result.ok or missing)
        if result.ok and images_removed:
            return None
        return "Docker Compose resource or checker image cleanup failed"

    def close(self) -> None:
        shutil.rmtree(self.temp, ignore_errors=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--compose-wrapper", required=True, type=Path)
    parser.add_argument("--compose-file", type=Path)
    parser.add_argument("--keep-stack", action="store_true")
    parser.add_argument("--build-timeout", type=float, default=900)
    parser.add_argument("--ready-timeout", type=float, default=60)
    return parser.parse_args(argv)


def _validated_report_path(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    parent = candidate.parent
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as error:
        raise FixtureError(f"Report directory is unavailable: {error}") from error
    if parent.absolute() != resolved_parent:
        raise FixtureError("Report directory must not contain symlinks")
    if candidate.is_symlink():
        raise FixtureError("Report path must not be a symlink")
    if candidate.exists() and not candidate.is_file():
        raise FixtureError("Report path must be a regular file")
    return resolved_parent / candidate.name


def _write_report(path: Path, report: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    started = utc_now()
    args = parse_args(argv)
    try:
        args.output = _validated_report_path(args.output)
    except (FixtureError, OSError) as error:
        print(f"Cannot initialize public report: {error}", file=sys.stderr)
        return 2
    checker: PublicChecker | None = None
    checks: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    exit_code = 2
    status = "error"
    try:
        checker = PublicChecker(args)
        checker.run_checks()
        checks = checker.checks
        commands = checker.harness.commands
        status = (
            "passed" if all(item["status"] == "passed" for item in checks) else "failed"
        )
        exit_code = 0 if status == "passed" else 1
    except ContractError as error:
        if checker is not None:
            checks = checker.checks
            commands = checker.harness.commands
        checks.append(
            {
                "name": "admission-contract",
                "phase": "admission",
                "status": "failed",
                "expected": "published candidate contract is available",
                "actual": _redact(str(error), (checker.secret,) if checker else ()),
            }
        )
        status = "failed"
        exit_code = 1
    except (FixtureError, EnvironmentFailure, OSError, ValueError) as error:
        if checker is not None:
            checks = checker.checks
            commands = checker.harness.commands
        checks.append(
            {
                "name": "checker-environment",
                "phase": "environment",
                "status": "failed",
                "expected": "checker initialization and local transports succeed",
                "actual": _redact(str(error), (checker.secret,) if checker else ()),
            }
        )
    except Exception as error:  # Checker defects are distinct from candidate failures.
        if checker is not None:
            checks = checker.checks
            commands = checker.harness.commands
        checks.append(
            {
                "name": "checker-internal-error",
                "phase": "environment",
                "status": "failed",
                "expected": "checker completes all phases",
                "actual": _redact(
                    f"{type(error).__name__}: {error}",
                    (checker.secret,) if checker else (),
                ),
            }
        )
    finally:
        if checker is not None:
            cleanup_error = checker.cleanup()
            commands = checker.harness.commands
            if cleanup_error:
                checks.append(
                    {
                        "name": "stack-cleanup",
                        "phase": "environment",
                        "status": "failed",
                        "expected": "compose down --volumes succeeds",
                        "actual": cleanup_error,
                    }
                )
                status = "error"
                exit_code = 2
            checker.close()
    report = build_report(
        started_at=started,
        finished_at=utc_now(),
        status=status,
        checks=checks,
        commands=commands,
    )
    if report_has_forbidden_keys(report):
        report = build_report(
            started_at=started,
            finished_at=utc_now(),
            status="error",
            checks=[
                {
                    "name": "checker-report-shape",
                    "phase": "environment",
                    "status": "failed",
                    "expected": "public-only report keys",
                    "actual": "forbidden report key detected",
                }
            ],
            commands=commands,
        )
        exit_code = 2
    try:
        _write_report(args.output, report)
    except OSError as error:
        print(f"Cannot write public report: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
