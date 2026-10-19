"""icepick schema v1 — validation and canonicalisation for bridge documents.

Two document kinds cross the bridge boundary:

* ``extract`` — IDA-produced inventory of one IDB (``ida_extract.v1.json``),
  written by the extractor that runs *inside* IDA (U-IDA2).
* ``labels`` — hand-authored external labels (``external_labels.json``),
  written by humans / format tools, never parsed by this bridge.

Both are plain JSON.  This module is stdlib-only and imports no IDA API:
the bridge validates and transports data, it never executes inside IDA.

Schema evolution rule: **additive only**.  Unknown keys are preserved by
normalisation and never rejected; every *known* key is checked hard so a
malformed document fails closed before it reaches the database.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

SCHEMA_VERSION = "v1"
SUPPORTED_SCHEMA_VERSIONS: tuple[str, ...] = (SCHEMA_VERSION,)
DOC_KINDS: tuple[str, ...] = ("extract", "labels")

#: Extraction backends the bridge knows how to provenance-tag.
BACKENDS: tuple[str, ...] = ("idalib", "idat")

EDGE_KINDS: tuple[str, ...] = (
    "call",
    "tail_call",
    "jump",
    "data_ref",
    "vtable",
    "other",
)

LABEL_KINDS: tuple[str, ...] = ("func", "data", "code", "unknown")
NAME_SOURCES: tuple[str, ...] = ("ida", "flirt", "manual", "dyn")
DOC_SOURCES: tuple[str, ...] = ("ida", "manual")
DECOMPILE_STATUSES: tuple[str, ...] = ("ok", "too_big", "timeout", "failed")

MAX_EA = (1 << 64) - 1
NAME_MAX_LEN = 256

DECOMPILE_FAILED_RE = re.compile(r"^DECOMPILE_FAILED\([a-z0-9_]+\)$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[^\s\x00-\x1f\x7f]+$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{1,16}$")


# --------------------------------------------------------------------------
# small shared helpers
# --------------------------------------------------------------------------
def parse_ea(value: Any) -> int | None:
    """Return ``value`` as an unsigned IDA effective address, else ``None``.

    Accepts plain integers and ``"0x..."`` hex strings (how human-authored
    label documents spell addresses).  Bare decimal strings are rejected on
    purpose: ``"4096"`` is ambiguous between decimal and hex.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= MAX_EA else None
    if isinstance(value, str) and _HEX_RE.match(value.strip()):
        parsed = int(value.strip(), 16)
        return parsed if 0 <= parsed <= MAX_EA else None
    return None


def is_ea(value: Any) -> bool:
    """True when ``value`` is a well-formed effective address."""
    return parse_ea(value) is not None


def _check_ea(value: Any, path: str, errors: list[str]) -> int | None:
    ea = parse_ea(value)
    if ea is None:
        errors.append(f"{path}: not a valid 64-bit effective address: {value!r}")
    return ea


def _check_name(value: Any, path: str) -> list[str]:
    if not isinstance(value, str) or not value:
        return [f"{path}: expected a non-empty string"]
    errors: list[str] = []
    if len(value) > NAME_MAX_LEN:
        errors.append(f"{path}: longer than {NAME_MAX_LEN} characters")
    if not NAME_RE.match(value):
        errors.append(f"{path}: must not contain whitespace or control characters")
    return errors


def _check_schema_version(obj: Mapping, path: str) -> list[str]:
    if "schema_version" not in obj:
        return [f"{path}.schema_version: missing (expected {SCHEMA_VERSION!r})"]
    version = obj["schema_version"]
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        return [
            f"{path}.schema_version: expected {SCHEMA_VERSION!r}, got {version!r}"
        ]
    return []


# --------------------------------------------------------------------------
# validation — returns a list of human-readable errors, empty when valid
# --------------------------------------------------------------------------
def validate_extract(obj: Any) -> list[str]:
    """Validate an extract document (``ida_extract.v1.json``).

    Returns ``[]`` when ``obj`` is a valid v1 extract, else one string per
    problem.  Never raises for malformed input.
    """
    if not isinstance(obj, Mapping):
        return [f"extract: expected a JSON object, got {type(obj).__name__}"]

    errors: list[str] = []
    errors.extend(_check_schema_version(obj, "extract"))
    errors.extend(_check_provenance(obj.get("provenance"), "extract.provenance"))

    funcs = obj.get("funcs")
    if not isinstance(funcs, list):
        errors.append("extract.funcs: expected a list")
    elif not funcs:
        errors.append("extract.funcs: expected at least one function")
    else:
        seen_eas: dict[int, str] = {}
        for index, func in enumerate(funcs):
            errors.extend(_check_func(func, f"extract.funcs[{index}]", seen_eas))

    edges = obj.get("edges")
    if edges is not None:
        if not isinstance(edges, list):
            errors.append("extract.edges: expected a list")
        else:
            seen_edges: set[tuple[int, int, str]] = set()
            for index, edge in enumerate(edges):
                errors.extend(
                    _check_edge(edge, f"extract.edges[{index}]", seen_edges)
                )
    return errors


def validate_labels(obj: Any) -> list[str]:
    """Validate an external label document (``external_labels.json`` v1)."""
    if not isinstance(obj, Mapping):
        return [f"labels: expected a JSON object, got {type(obj).__name__}"]

    errors: list[str] = []
    errors.extend(_check_schema_version(obj, "labels"))

    source = obj.get("source")
    if source is not None and source not in DOC_SOURCES:
        errors.append(
            f"labels.source: expected one of 'manual', 'ida'; got {source!r}"
        )
    if source == "ida":
        errors.append(
            "labels.source: external label documents must declare source='manual'"
        )

    idb_sha = obj.get("idb_sha256")
    if idb_sha is not None and (
        not isinstance(idb_sha, str) or not SHA256_RE.match(idb_sha)
    ):
        errors.append(
            "labels.idb_sha256: expected a lowercase 64-char hex sha256"
        )

    generator = obj.get("generator")
    if generator is not None and (
        not isinstance(generator, str) or not generator.strip()
    ):
        errors.append("labels.generator: expected a non-empty string")

    labels = obj.get("labels")
    if not isinstance(labels, list):
        errors.append("labels.labels: expected a list")
    elif not labels:
        errors.append("labels.labels: expected at least one label")
    else:
        seen: set[tuple[int, str]] = set()
        for index, label in enumerate(labels):
            errors.extend(
                _check_label(label, f"labels.labels[{index}]", seen)
            )
    return errors


def validate_document(kind: str, obj: Any) -> list[str]:
    """Dispatch to :func:`validate_extract` / :func:`validate_labels`."""
    if kind == "extract":
        return validate_extract(obj)
    if kind == "labels":
        return validate_labels(obj)
    raise ValueError(f"unknown document kind: {kind!r} (expected one of {DOC_KINDS})")


def _check_provenance(prov: Any, path: str) -> list[str]:
    if not isinstance(prov, Mapping):
        return [
            f"{path}: expected a JSON object with "
            "ida_version/idb_sha256/auto_analysis/backend"
        ]
    errors: list[str] = []
    required = ("ida_version", "idb_sha256", "auto_analysis", "backend")
    for key in required:
        if key not in prov:
            errors.append(f"{path}.{key}: missing required provenance field")

    ida_version = prov.get("ida_version")
    if ida_version is not None and (
        not isinstance(ida_version, str) or not ida_version.strip()
    ):
        errors.append(f"{path}.ida_version: expected a non-empty string")

    idb_sha = prov.get("idb_sha256")
    if idb_sha is not None and (
        not isinstance(idb_sha, str) or not SHA256_RE.match(idb_sha)
    ):
        errors.append(f"{path}.idb_sha256: expected a lowercase 64-char hex sha256")

    auto = prov.get("auto_analysis")
    if auto is not None and not isinstance(auto, bool):
        errors.append(f"{path}.auto_analysis: expected true or false")

    backend = prov.get("backend")
    if backend is not None and backend not in BACKENDS:
        errors.append(
            f"{path}.backend: expected one of 'idalib', 'idat'; got {backend!r}"
        )

    generator = prov.get("generator")
    if generator is not None and (
        not isinstance(generator, str) or not generator.strip()
    ):
        errors.append(f"{path}.generator: expected a non-empty string")

    sigs = prov.get("sigs_applied")
    if sigs is not None:
        if not isinstance(sigs, list):
            errors.append(f"{path}.sigs_applied: expected a list of entries")
        else:
            for index, entry in enumerate(sigs):
                epath = f"{path}.sigs_applied[{index}]"
                if not isinstance(entry, Mapping):
                    errors.append(f"{epath}: expected an object with a 'name'")
                    continue
                name = entry.get("name")
                if not isinstance(name, str) or not name.strip():
                    errors.append(f"{epath}.name: expected a non-empty string")
                for key in ("version", "sha"):
                    value = entry.get(key)
                    if value is not None and not isinstance(value, str):
                        errors.append(
                            f"{epath}.{key}: expected a string or null"
                        )
    return errors


def _check_func(func: Any, path: str, seen_eas: dict[int, str]) -> list[str]:
    if not isinstance(func, Mapping):
        return [f"{path}: expected a JSON object, got {type(func).__name__}"]

    errors: list[str] = []
    ea = _check_ea(func.get("ea"), f"{path}.ea", errors)
    if ea is not None:
        if ea in seen_eas:
            errors.append(
                f"{path}.ea: duplicate effective address {ea:#x} "
                f"(first seen at {seen_eas[ea]})"
            )
        else:
            seen_eas[ea] = path

    errors.extend(_check_name(func.get("name"), f"{path}.name"))

    name_source = func.get("name_source", "ida")
    if name_source not in NAME_SOURCES:
        errors.append(
            f"{path}.name_source: expected one of "
            f"{', '.join(repr(s) for s in NAME_SOURCES)}; got {name_source!r}"
        )

    source = func.get("source")
    if source is not None and source not in DOC_SOURCES:
        errors.append(
            f"{path}.source: expected one of 'ida', 'manual'; got {source!r}"
        )

    flags = func.get("flags", [])
    if not isinstance(flags, list) or not all(
        isinstance(flag, str) and flag for flag in flags
    ):
        errors.append(f"{path}.flags: expected a list of non-empty strings")

    for key in ("size", "blocks"):
        value = func.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{path}.{key}: expected a non-negative integer or null")

    for key in ("callers", "callees"):
        value = func.get(key)
        if value is None:
            continue
        if not isinstance(value, list):
            errors.append(f"{path}.{key}: expected a list of effective addresses")
            continue
        for index, item in enumerate(value):
            _check_ea(item, f"{path}.{key}[{index}]", errors)

    decompiled = func.get("decompiled")
    if decompiled is not None and not isinstance(decompiled, str):
        errors.append(f"{path}.decompiled: expected a string or null")

    status = func.get("decompile_status")
    if status is not None and status not in DECOMPILE_STATUSES:
        errors.append(
            f"{path}.decompile_status: expected one of 'ok', 'failed'; got {status!r}"
        )

    if isinstance(decompiled, str):
        if status == "failed":
            errors.append(
                f"{path}: decompiled text is present but decompile_status is 'failed'"
            )
    else:
        if status == "ok":
            errors.append(
                f"{path}.decompile_status: 'ok' requires decompiled text"
            )
        error = func.get("decompile_error")
        if not (isinstance(error, str) and DECOMPILE_FAILED_RE.match(error)):
            errors.append(
                f"{path}.decompile_error: expected a DECOMPILE_FAILED(<reason>) "
                "sentinel when decompiled is null"
            )
    return errors


def _check_edge(
    edge: Any, path: str, seen: set[tuple[int, int, str]]
) -> list[str]:
    if not isinstance(edge, Mapping):
        return [f"{path}: expected a JSON object, got {type(edge).__name__}"]
    errors: list[str] = []
    src = _check_ea(edge.get("src"), f"{path}.src", errors)
    dst = _check_ea(edge.get("dst"), f"{path}.dst", errors)
    kind = edge.get("kind", "call")
    if kind not in EDGE_KINDS:
        errors.append(
            f"{path}.kind: expected one of "
            f"{', '.join(repr(k) for k in EDGE_KINDS)}; got {kind!r}"
        )
    if src is not None and dst is not None and kind in EDGE_KINDS:
        key = (src, dst, kind)
        if key in seen:
            errors.append(
                f"{path}: duplicate edge {src:#x} -> {dst:#x} ({kind})"
            )
        else:
            seen.add(key)
    return errors


def _check_label(
    label: Any, path: str, seen: set[tuple[int, str]]
) -> list[str]:
    if not isinstance(label, Mapping):
        return [f"{path}: expected a JSON object, got {type(label).__name__}"]
    errors: list[str] = []
    ea = _check_ea(label.get("ea"), f"{path}.ea", errors)
    errors.extend(_check_name(label.get("name"), f"{path}.name"))

    kind = label.get("kind")
    if kind not in LABEL_KINDS:
        errors.append(
            f"{path}.kind: expected one of "
            f"{', '.join(repr(k) for k in LABEL_KINDS)}; got {kind!r}"
        )
    elif ea is not None:
        key = (ea, kind)
        if key in seen:
            errors.append(f"{path}: duplicate label for {ea:#x} kind {kind!r}")
        else:
            seen.add(key)

    for key in ("type", "prototype", "note", "author", "origin"):
        value = label.get(key)
        if value is not None and not isinstance(value, str):
            errors.append(f"{path}.{key}: expected a string")
    return errors


# --------------------------------------------------------------------------
# canonicalisation + digests (basis of the exactly-once ingest guarantee)
# --------------------------------------------------------------------------
def canonical_json(obj: Any) -> str:
    """Deterministic JSON text: sorted keys, no incidental whitespace."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def content_digest(obj: Any) -> str:
    """sha256 over :func:`canonical_json`."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def _sorted_eas(values: Any) -> list[int]:
    parsed: set[int] = set()
    for value in values or []:
        ea = parse_ea(value)
        if ea is not None:
            parsed.add(ea)
    return sorted(parsed)


def _norm_func(func: Mapping) -> dict:
    decompiled = func.get("decompiled")
    if isinstance(decompiled, str):
        status = func.get("decompile_status") or "ok"
    else:
        status = func.get("decompile_status") or "failed"
    flags = [flag for flag in (func.get("flags") or []) if isinstance(flag, str)]
    return {
        "ea": parse_ea(func.get("ea")),
        "name": func.get("name"),
        "name_source": func.get("name_source", "ida"),
        "flags": sorted(set(flags)),
        "size": func.get("size"),
        "blocks": func.get("blocks"),
        "callers": _sorted_eas(func.get("callers")),
        "callees": _sorted_eas(func.get("callees")),
        "decompiled": decompiled if isinstance(decompiled, str) else None,
        "decompile_status": status,
        "decompile_error": func.get("decompile_error")
        if isinstance(func.get("decompile_error"), str)
        else None,
    }


def _norm_provenance(prov: Mapping) -> dict:
    normalized = {
        "ida_version": prov.get("ida_version"),
        "idb_sha256": prov.get("idb_sha256"),
        "auto_analysis": bool(prov.get("auto_analysis")),
        "backend": prov.get("backend"),
    }
    generator = prov.get("generator")
    if isinstance(generator, str) and generator.strip():
        normalized["generator"] = generator
    return normalized


def collect_edges(obj: Mapping) -> list[dict]:
    """Canonical, de-duplicated, sorted edge list for an extract document.

    Uses the explicit ``edges`` array when present; otherwise derives call
    edges from each function's ``callees``.  Call only on a validated
    document.
    """
    raw = obj.get("edges")
    pairs: set[tuple[int, int, str]] = set()
    if raw is not None:
        for index, edge in enumerate(raw):
            src = parse_ea(edge.get("src"))
            dst = parse_ea(edge.get("dst"))
            kind = edge.get("kind", "call")
            if src is None or dst is None or kind not in EDGE_KINDS:
                raise ValueError(f"extract.edges[{index}]: unvalidated edge")
            pairs.add((src, dst, kind))
    else:
        for func in obj.get("funcs", []):
            src = parse_ea(func.get("ea"))
            if src is None:
                raise ValueError("extract.funcs: unvalidated function address")
            for callee in func.get("callees") or []:
                dst = parse_ea(callee)
                if dst is None:
                    raise ValueError("extract.funcs.callees: unvalidated address")
                pairs.add((src, dst, "call"))
    return [
        {"src": src, "dst": dst, "kind": kind} for src, dst, kind in sorted(pairs)
    ]


def normalize_extract(obj: Mapping) -> dict:
    """Canonical form of a validated extract document.

    Address order, flag order, key order and idle whitespace never affect the
    result, so two semantically identical documents digest identically.
    """
    funcs = [_norm_func(func) for func in obj.get("funcs", [])]
    funcs.sort(key=lambda func: func["ea"])
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "extract",
        "doc_source": "ida",
        "provenance": _norm_provenance(obj.get("provenance") or {}),
        "funcs": funcs,
        "edges": collect_edges(obj),
    }


def normalize_labels(obj: Mapping) -> dict:
    """Canonical form of a validated label document."""
    labels = []
    for label in obj.get("labels", []):
        labels.append(
            {
                "ea": parse_ea(label.get("ea")),
                "name": label.get("name"),
                "kind": label.get("kind"),
                "type": label.get("type"),
                "prototype": label.get("prototype"),
                "note": label.get("note"),
            }
        )
    labels.sort(key=lambda label: (label["kind"], label["ea"]))
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "kind": "labels",
        "doc_source": "manual",
        "labels": labels,
    }
    idb_sha = obj.get("idb_sha256")
    if idb_sha is not None:
        normalized["idb_sha256"] = idb_sha
    generator = obj.get("generator")
    if generator is not None:
        normalized["generator"] = generator
    return normalized


def extract_digest(obj: Mapping) -> str:
    """Digest of the canonical extract (stable across formatting noise)."""
    return content_digest(normalize_extract(obj))


def labels_digest(obj: Mapping) -> str:
    """Digest of the canonical label document."""
    return content_digest(normalize_labels(obj))


def document_digest(kind: str, obj: Mapping) -> str:
    if kind == "extract":
        return extract_digest(obj)
    if kind == "labels":
        return labels_digest(obj)
    raise ValueError(f"unknown document kind: {kind!r} (expected one of {DOC_KINDS})")


# --------------------------------------------------------------------------
# loading convenience
# --------------------------------------------------------------------------
def load_json(path: Any) -> Any:
    """Read a UTF-8 JSON document from ``path``."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_and_validate(kind: str, path: Any) -> tuple[Any, list[str]]:
    """Load a document and validate it; returns ``(obj, errors)``."""
    obj = load_json(path)
    return obj, validate_document(kind, obj)
