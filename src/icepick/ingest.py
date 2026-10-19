"""icepick ingest — bridge documents into a SQLite analysis database.

Two entry points, both idempotent and both provenance-tagged:

``ingest_extract()``
    Takes a validated ``ida_extract.v1.json`` document, writes ``funcs`` and
    ``edges`` rows tagged ``source='ida'``, and records one ``provenance``
    row keyed by the document digest.

``ingest_manual()``
    Takes a validated ``external_labels.json`` (v1) document, writes ``labels``
    rows tagged ``source='manual'`` and mirrors ``kind='func'`` labels into
    ``funcs`` with ``name_source='manual'`` — which outranks every IDA-derived
    name (``ida``/``flirt``) permanently: a later extract re-ingest never
    overwrites a manual name.

Exactly-once: the identity of a document is the sha256 of its *canonical*
form (:mod:`icepick.schema`), so whitespace, key order, array order and hex
vs. int address spelling cannot produce a second write.  Re-ingesting the same
canonical document is a no-op — nothing is written and the database file stays
byte-identical.  ``force=True`` re-applies it deliberately (manual names still
win) for callers that want a rebuild.

Stdlib only: ``sqlite3`` / ``json`` / ``pathlib`` (plus ``icepick.schema``).
Nothing in this module knows IDA exists — that is the whole point of the seam.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import schema
from .schema import SCHEMA_VERSION

__all__ = [
    "INGEST_VERSION",
    "SOURCE_IDA",
    "SOURCE_MANUAL",
    "NAME_SOURCE_RANK",
    "IngestError",
    "SCHEMA_SQL",
    "ensure_schema",
    "ingest_extract",
    "ingest_manual",
    "ingest_file",
    "ingest_many",
    "canonical_digest",
    "main",
]

INGEST_VERSION = "v1"
SOURCE_IDA = "ida"
SOURCE_MANUAL = "manual"

#: Higher rank wins when two documents name the same address.
NAME_SOURCE_RANK: dict[str, int] = {
    "ida": 10,
    "flirt": 15,
    "manual": 20,
    "dyn": 30,  # dynamic receipts stay above manual labels (README contract)
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS funcs (
    ea                INTEGER PRIMARY KEY,
    name              TEXT    NOT NULL,
    name_source       TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    name_rank         INTEGER NOT NULL DEFAULT 0,
    flags             TEXT    NOT NULL DEFAULT '[]',
    size              INTEGER,
    blocks            INTEGER,
    decompiled        TEXT,
    decompile_status  TEXT,
    decompile_error   TEXT,
    doc_digest        TEXT,
    updated_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS edges (
    src        INTEGER NOT NULL,
    dst        INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    source     TEXT    NOT NULL,
    doc_digest TEXT,
    PRIMARY KEY (src, dst, kind, source)
);

CREATE TABLE IF NOT EXISTS labels (
    ea         INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    type       TEXT,
    prototype  TEXT,
    note       TEXT,
    source     TEXT    NOT NULL,
    doc_digest TEXT,
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (ea, kind, name)
);

CREATE TABLE IF NOT EXISTS provenance (
    doc_kind       TEXT    NOT NULL,
    doc_id         TEXT    NOT NULL,
    doc_digest     TEXT    NOT NULL,
    schema_version TEXT    NOT NULL,
    doc_source     TEXT    NOT NULL,
    ida_version    TEXT,
    idb_sha256     TEXT,
    auto_analysis  INTEGER,
    backend        TEXT,
    generator      TEXT,
    source_path    TEXT,
    funcs          INTEGER NOT NULL DEFAULT 0,
    edges          INTEGER NOT NULL DEFAULT 0,
    labels         INTEGER NOT NULL DEFAULT 0,
    ingested_at    TEXT    NOT NULL,
    PRIMARY KEY (doc_kind, doc_id)
);

CREATE INDEX IF NOT EXISTS idx_funcs_name ON funcs(name);
CREATE INDEX IF NOT EXISTS idx_funcs_name_source ON funcs(name_source);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_labels_ea ON labels(ea);
CREATE INDEX IF NOT EXISTS idx_provenance_doc_id ON provenance(doc_id);
"""


class IngestError(ValueError):
    """Raised when a document fails validation or a target cannot be opened."""


# --------------------------------------------------------------------------
# connection plumbing
# --------------------------------------------------------------------------
def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _is_connection(target: Any) -> bool:
    return isinstance(target, sqlite3.Connection)


@contextmanager
def _connect(target: Any):
    """Yield ``(connection, owns_connection)`` for a path or live connection."""
    if _is_connection(target):
        yield target, False
        return
    if isinstance(target, (str, Path)):
        path = Path(target)
        if str(path) != ":memory:" and path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn, True
        finally:
            conn.close()
        return
    raise IngestError(
        "target must be a filesystem path or an open sqlite3.Connection, "
        f"got {type(target).__name__}"
    )


def ensure_schema(target: Any) -> None:
    """Create the ingest schema in ``target`` (path or connection), if absent."""
    with _connect(target) as (conn, owns):
        _apply_schema(conn)
        if owns:
            conn.commit()


def _apply_schema(conn: sqlite3.Connection) -> None:
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    # Cheap presence probe: re-issuing DDL against an already-populated
    # database can rewrite the file header, which would break the
    # byte-identical re-ingest guarantee.
    row = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN "
        "('funcs', 'edges', 'labels', 'provenance')"
    ).fetchone()
    if row is not None and row[0] == 4:
        return
    conn.executescript(SCHEMA_SQL)


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------
def _document(doc: Any, obj: Any, func_name: str) -> Mapping:
    if doc is None:
        doc = obj
    if doc is None:
        raise IngestError(
            f"{func_name}() requires a document: pass the decoded JSON object "
            "as the second positional argument"
        )
    if isinstance(doc, (str, Path)):
        path = Path(doc)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise IngestError(f"{func_name}(): cannot read document {path}: {exc}")
    if not isinstance(doc, Mapping):
        raise IngestError(
            f"{func_name}(): document must be a JSON object, got {type(doc).__name__}"
        )
    return doc


def _validated(kind: str, doc: Mapping, func_name: str) -> Mapping:
    errors = schema.validate_document(kind, doc)
    if errors:
        raise IngestError(
            f"{func_name}(): {kind} document failed validation "
            f"({len(errors)} problem(s)):\n  - " + "\n  - ".join(errors)
        )
    return doc


def _normalized(kind: str, doc: Mapping) -> dict:
    if kind == "extract":
        return schema.normalize_extract(doc)
    return schema.normalize_labels(doc)


def canonical_digest(kind: str, doc: Mapping) -> str:
    """Canonical content digest — the exactly-once identity of a document."""
    return schema.content_digest(_normalized(kind, doc))


def _already_ingested(conn: sqlite3.Connection, kind: str, digest: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM provenance WHERE doc_kind = ? AND doc_id = ?",
            (kind, digest),
        ).fetchone()
        is not None
    )


def _record_provenance(
    conn: sqlite3.Connection,
    *,
    kind: str,
    digest: str,
    doc_source: str,
    provenance: Mapping | None,
    counts: Mapping[str, int],
    source_path: Any = None,
    now: str,
) -> None:
    prov = provenance or {}
    auto = prov.get("auto_analysis")
    conn.execute(
        """
        INSERT OR REPLACE INTO provenance (
            doc_kind, doc_id, doc_digest, schema_version, doc_source,
            ida_version, idb_sha256, auto_analysis, backend, generator,
            source_path, funcs, edges, labels, ingested_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            kind,
            digest,
            digest,
            SCHEMA_VERSION,
            doc_source,
            prov.get("ida_version"),
            prov.get("idb_sha256"),
            None if auto is None else int(bool(auto)),
            prov.get("backend"),
            prov.get("generator"),
            str(source_path) if source_path is not None else None,
            int(counts.get("funcs", 0)),
            int(counts.get("edges", 0)),
            int(counts.get("labels", 0)),
            now,
        ),
    )


def _report(kind: str, digest: str) -> dict:
    return {
        "kind": kind,
        "version": INGEST_VERSION,
        "schema_version": SCHEMA_VERSION,
        "digest": digest,
        "applied": False,
        "skipped_reason": None,
        "funcs_inserted": 0,
        "funcs_updated": 0,
        "funcs_unchanged": 0,
        "funcs_removed": 0,
        "edges_inserted": 0,
        "labels_inserted": 0,
        "labels_updated": 0,
        "labels_unchanged": 0,
        "funcs_count": 0,
        "edges_count": 0,
        "labels_count": 0,
        "name_precedence_collisions": [],
        "provenance": "unchanged",
    }


# --------------------------------------------------------------------------
# ingest_extract
# --------------------------------------------------------------------------
def ingest_extract(
    target: Any,
    doc: Any = None,
    *,
    obj: Any = None,
    source_path: Any = None,
    force: bool = False,
    conn: Any = None,
) -> dict:
    """Upsert an IDA extract into ``funcs``/``edges``/``provenance``.

    ``target`` is a database path (``str``/``Path``) or an open
    ``sqlite3.Connection``; ``doc`` is the decoded extract document or a path
    to a JSON file.  Returns a JSON-serialisable report dict.

    Idempotent: a second call with the same canonical document performs no
    write at all (``applied`` is ``False``,
    ``skipped_reason == 'already-ingested'``).
    """
    if conn is not None:
        target = conn
    document = _validated(
        "extract", _document(doc, obj, "ingest_extract"), "ingest_extract"
    )
    normalized = schema.normalize_extract(document)
    digest = schema.content_digest(normalized)
    report = _report("extract", digest)
    now = _utc_now()

    with _connect(target) as (db, owns):
        _apply_schema(db)
        if _already_ingested(db, "extract", digest) and not force:
            report["skipped_reason"] = "already-ingested"
            return report

        report["applied"] = True
        collisions: list[dict] = []
        doc_eas: list[int] = []

        # ---- funcs ------------------------------------------------------
        for func in normalized["funcs"]:
            ea = func["ea"]
            doc_eas.append(ea)
            incoming_name_source = func["name_source"] or SOURCE_IDA
            incoming_rank = NAME_SOURCE_RANK.get(incoming_name_source, 0)
            existing = db.execute("SELECT * FROM funcs WHERE ea = ?", (ea,)).fetchone()

            if existing is None:
                db.execute(
                    """
                    INSERT INTO funcs (ea, name, name_source, source, name_rank,
                                       flags, size, blocks, decompiled,
                                       decompile_status, decompile_error,
                                       doc_digest, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ea,
                        func["name"],
                        incoming_name_source,
                        SOURCE_IDA,
                        incoming_rank,
                        json.dumps(func["flags"]),
                        func["size"],
                        func["blocks"],
                        func["decompiled"],
                        func["decompile_status"],
                        func["decompile_error"],
                        digest,
                        now,
                    ),
                )
                report["funcs_inserted"] += 1
                continue

            current_rank = int(existing["name_rank"] or 0)
            if current_rank > incoming_rank:
                # manual (or dynamic) knowledge outranks the extract: keep it.
                if existing["name"] != func["name"]:
                    collisions.append(
                        {
                            "ea": ea,
                            "kept": existing["name"],
                            "kept_source": existing["name_source"],
                            "offered": func["name"],
                            "offered_source": incoming_name_source,
                        }
                    )
                name = existing["name"]
                name_source = existing["name_source"]
                name_rank = current_rank
            else:
                name = func["name"]
                name_source = incoming_name_source
                name_rank = max(incoming_rank, current_rank)

            same_payload = (
                existing["size"] == func["size"]
                and existing["blocks"] == func["blocks"]
                and existing["decompiled"] == func["decompiled"]
                and json.loads(existing["flags"] or "[]") == func["flags"]
                and existing["decompile_status"] == func["decompile_status"]
                and existing["decompile_error"] == func["decompile_error"]
            )
            db.execute(
                """
                UPDATE funcs SET name = ?, name_source = ?, name_rank = ?,
                                 flags = ?, size = ?, blocks = ?, decompiled = ?,
                                 decompile_status = ?, decompile_error = ?,
                                 doc_digest = ?, updated_at = ?
                 WHERE ea = ?
                """,
                (
                    name,
                    name_source,
                    name_rank,
                    json.dumps(func["flags"]),
                    func["size"],
                    func["blocks"],
                    func["decompiled"],
                    func["decompile_status"],
                    func["decompile_error"],
                    digest,
                    now,
                    ea,
                ),
            )
            if name != existing["name"] or not same_payload:
                report["funcs_updated"] += 1
            else:
                report["funcs_unchanged"] += 1

        # ---- edges ------------------------------------------------------
        edges = schema.collect_edges(document)
        for src in doc_eas:
            db.execute(
                "DELETE FROM edges WHERE source = ? AND src = ?", (SOURCE_IDA, src)
            )
        for edge in edges:
            db.execute(
                """
                INSERT OR REPLACE INTO edges (src, dst, kind, source, doc_digest)
                VALUES (?, ?, ?, ?, ?)
                """,
                (edge["src"], edge["dst"], edge["kind"], SOURCE_IDA, digest),
            )
        report["edges_inserted"] = len(edges)

        if force and doc_eas:
            placeholders = ",".join("?" * len(doc_eas))
            stale = db.execute(
                "SELECT COUNT(*) FROM funcs WHERE source = ? AND ea NOT IN "
                f"({placeholders})",
                (SOURCE_IDA, *doc_eas),
            ).fetchone()[0]
            db.execute(
                "DELETE FROM funcs WHERE source = ? AND ea NOT IN "
                f"({placeholders})",
                (SOURCE_IDA, *doc_eas),
            )
            report["funcs_removed"] = int(stale)

        counts = {"funcs": len(normalized["funcs"]), "edges": len(edges)}
        _record_provenance(
            db,
            kind="extract",
            digest=digest,
            doc_source=SOURCE_IDA,
            provenance=normalized.get("provenance") or {},
            counts=counts,
            source_path=source_path,
            now=now,
        )
        report["provenance"] = "inserted"
        report["funcs_count"] = counts["funcs"]
        report["edges_count"] = counts["edges"]
        report["name_precedence_collisions"] = collisions
        if owns:
            db.commit()
    return report


# --------------------------------------------------------------------------
# ingest_manual
# --------------------------------------------------------------------------
def ingest_manual(
    target: Any,
    doc: Any = None,
    *,
    obj: Any = None,
    source_path: Any = None,
    force: bool = False,
    conn: Any = None,
) -> dict:
    """Merge hand-authored labels, tagging them ``source='manual'``.

    Manual names outrank IDA hints (``ida``/``flirt``) in ``funcs`` forever:
    subsequent extract ingests can never rename them.  Idempotent in the same
    canonical-digest sense as :func:`ingest_extract`.
    """
    if conn is not None:
        target = conn
    document = _validated(
        "labels", _document(doc, obj, "ingest_manual"), "ingest_manual"
    )
    normalized = schema.normalize_labels(document)
    digest = schema.content_digest(normalized)
    report = _report("labels", digest)
    now = _utc_now()

    with _connect(target) as (db, owns):
        _apply_schema(db)
        if _already_ingested(db, "labels", digest) and not force:
            report["skipped_reason"] = "already-ingested"
            return report

        report["applied"] = True
        rank = NAME_SOURCE_RANK[SOURCE_MANUAL]

        for label in normalized["labels"]:
            ea = label["ea"]
            kind = label["kind"]
            existing = db.execute(
                "SELECT * FROM labels WHERE ea = ? AND kind = ? AND name = ?",
                (ea, kind, label["name"]),
            ).fetchone()
            if existing is None:
                db.execute(
                    """
                    INSERT INTO labels (ea, kind, name, type, prototype, note,
                                        source, doc_digest, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ea,
                        kind,
                        label["name"],
                        label["type"],
                        label["prototype"],
                        label["note"],
                        SOURCE_MANUAL,
                        digest,
                        now,
                    ),
                )
                report["labels_inserted"] += 1
            else:
                same_payload = (
                    existing["type"] == label["type"]
                    and existing["prototype"] == label["prototype"]
                    and existing["note"] == label["note"]
                )
                db.execute(
                    """
                    UPDATE labels SET type = ?, prototype = ?, note = ?,
                                      source = ?, doc_digest = ?, updated_at = ?
                     WHERE ea = ? AND kind = ? AND name = ?
                    """,
                    (
                        label["type"],
                        label["prototype"],
                        label["note"],
                        SOURCE_MANUAL,
                        digest,
                        now,
                        ea,
                        kind,
                        label["name"],
                    ),
                )
                if same_payload:
                    report["labels_unchanged"] += 1
                else:
                    report["labels_updated"] += 1

            if kind != "func":
                continue

            func_row = db.execute("SELECT * FROM funcs WHERE ea = ?", (ea,)).fetchone()
            if func_row is None:
                db.execute(
                    """
                    INSERT INTO funcs (ea, name, name_source, source, name_rank,
                                       flags, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ea, label["name"], SOURCE_MANUAL, SOURCE_MANUAL, rank, "[]", now),
                )
                report["funcs_inserted"] += 1
            elif label["name"] != func_row["name"]:
                db.execute(
                    """
                    UPDATE funcs SET name = ?, name_source = ?, name_rank = ?,
                                     source = ?, updated_at = ?
                     WHERE ea = ?
                    """,
                    (label["name"], SOURCE_MANUAL, rank, SOURCE_MANUAL, now, ea),
                )
                report["funcs_updated"] += 1
            elif func_row["name_source"] != SOURCE_MANUAL:
                db.execute(
                    """
                    UPDATE funcs SET name_source = ?, name_rank = ?, source = ?,
                                     updated_at = ?
                     WHERE ea = ?
                    """,
                    (SOURCE_MANUAL, rank, SOURCE_MANUAL, now, ea),
                )
                report["funcs_updated"] += 1
            else:
                report["funcs_unchanged"] += 1

        counts = {"labels": len(normalized["labels"])}
        _record_provenance(
            db,
            kind="labels",
            digest=digest,
            doc_source=SOURCE_MANUAL,
            provenance={
                "generator": normalized.get("generator"),
                "idb_sha256": normalized.get("idb_sha256"),
            },
            counts=counts,
            source_path=source_path,
            now=now,
        )
        report["provenance"] = "inserted"
        report["labels_count"] = counts["labels"]
        if owns:
            db.commit()
    return report


# --------------------------------------------------------------------------
# file convenience
# --------------------------------------------------------------------------
def _infer_kind(document: Any) -> str:
    declared = document.get("kind") if isinstance(document, Mapping) else None
    if declared in schema.DOC_KINDS:
        return declared
    if isinstance(document, Mapping) and "labels" in document:
        return "labels"
    return "extract"


def ingest_file(
    target: Any, path: Any, *, kind: str | None = None, force: bool = False
) -> dict:
    """Ingest ``path``, inferring the document kind when ``kind`` is ``None``."""
    source = Path(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IngestError(f"ingest_file(): cannot read document {source}: {exc}")

    if kind is None:
        kind = _infer_kind(document)
    if kind == "extract":
        return ingest_extract(target, document, source_path=source, force=force)
    if kind == "labels":
        return ingest_manual(target, document, source_path=source, force=force)
    raise IngestError(f"ingest_file(): unknown document kind: {kind!r}")


def ingest_many(
    target: Any, paths: Iterable[Any], *, force: bool = False
) -> list[dict]:
    """Ingest several documents in the order given."""
    return [ingest_file(target, path, force=force) for path in paths]


def main(argv: list[str] | None = None) -> int:
    """``python -m icepick.ingest`` → the icepick CLI."""
    from .cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
