"""icepick command line — argparse front door for the ingest and extract lanes.

::

    icepick ingest        analysis.db tests/data/ida_extract.v1.json
    icepick ingest-manual analysis.db external_labels.json
    icepick show          analysis.db
    icepick extract       target.exe --backend idalib --out extract.json
    icepick diff-import   diff.sqlite --out candidates.json

``ingest`` takes IDA extract documents, ``ingest-manual`` takes hand-authored
label documents.  Both are exactly-once: re-running the same document reports
``already-ingested`` and writes nothing.  ``extract`` runs the IDA-side lane and
prints (or writes) the deterministic schema-v1 document.  Exit codes: ``0`` ok,
``1`` failure (validation/IDA errors go to stderr and nothing is written), ``2``
usage.

This module never touches IDA: ``extract`` is imported lazily inside
:func:`cmd_extract`, so ``import icepick.cli`` stays IDA-free and an
IDA-less machine can still run every other lane.  Stdlib only: ``argparse`` /
``json`` / ``sqlite3`` / ``pathlib``.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Sequence

from . import __version__, diff, schema
from .ingest import IngestError, ingest_file

PROG = "icepick"

#: ``ingest`` treats bare documents as extracts; ``ingest-manual`` as labels.
LANE_KINDS = {"ingest": "extract", "ingest-manual": "labels"}


def build_parser() -> argparse.ArgumentParser:
    """Build the icepick argument parser."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "icepick — deterministic IDA Pro bridge: ingest versioned, "
            "provenance-tagged JSON into a SQLite analysis database."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} {__version__} (schema {schema.SCHEMA_VERSION})",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    def add_ingest(name: str, kind: str, help_text: str) -> None:
        lane = sub.add_parser(name, help=help_text, description=help_text)
        lane.add_argument("db", metavar="DB", help="SQLite analysis database path")
        lane.add_argument(
            "documents",
            metavar="DOCUMENT",
            nargs="+",
            help=f"{kind} JSON document(s) to ingest",
        )
        lane.add_argument(
            "--kind",
            choices=list(schema.DOC_KINDS),
            default=None,
            help=(
                "force the document kind instead of inferring it "
                f"(this subcommand defaults to {kind})"
            ),
        )
        lane.add_argument(
            "--force",
            action="store_true",
            help="re-apply a document that was already ingested",
        )
        lane.add_argument(
            "--dry-run",
            action="store_true",
            help="validate documents and report, but write nothing",
        )
        lane.add_argument(
            "--json",
            dest="as_json",
            action="store_true",
            help="emit machine-readable JSON reports",
        )
        lane.add_argument(
            "--quiet",
            action="store_true",
            help="print nothing on success (exit code only)",
        )

    add_ingest("ingest", "extract", "Ingest IDA extract documents (source='ida').")
    add_ingest(
        "ingest-manual",
        "labels",
        "Ingest hand-authored labels (source='manual'), outranking IDA names.",
    )

    # ``extract`` is the IDA-side lane.  Its flags mirror icepick.extract, but
    # they are declared here so building the parser never imports that module
    # (and therefore never even loads the IDA-facing code path).
    lane = sub.add_parser(
        "extract",
        help="Extract a schema-v1 inventory from an IDB (needs idalib or IDA).",
        description=(
            "Extract a deterministic schema-v1 inventory from an IDB (or from "
            "the database IDA already has open) and write it as JSON."
        ),
    )
    lane.add_argument(
        "target",
        metavar="INPUT",
        help="input binary (or IDB/IDC) to analyse; the hosted database is used "
        "when running inside IDA",
    )
    lane.add_argument(
        "-o",
        "--out",
        metavar="OUT",
        default=None,
        help="write the extract JSON here (default: stdout)",
    )
    lane.add_argument(
        "--top-k",
        dest="top_k",
        type=int,
        default=None,
        metavar="N",
        help="cap each xref/caller/callee/CFG list at N entries "
        "(default: icepick.extract.DEFAULT_TOP_K)",
    )
    lane.add_argument(
        "--backend",
        choices=list(schema.BACKENDS),
        default=None,
        help="provenance backend tag (default: idat when hosted, idalib standalone)",
    )
    lane.add_argument(
        "--ida-home",
        dest="ida_home",
        metavar="DIR",
        default=None,
        help="IDA install directory to pin as IDADIR (default: ida-config.json)",
    )
    lane.add_argument(
        "--trust-env-idadir",
        dest="trust_env_idadir",
        action="store_true",
        help="trust the inherited IDADIR (ignored by default: a harness shell's "
        "value is stale)",
    )
    lane.add_argument(
        "--apply-names",
        dest="apply_names",
        action="store_true",
        help="not implemented: extraction is read-only and never writes the IDB",
    )
    lane.add_argument(
        "--sigs",
        dest="sigs",
        metavar="SIG",
        action="append",
        default=None,
        help="private FLIRT signature file to apply (repeatable, best-effort)",
    )
    lane.add_argument(
        "--quiet",
        action="store_true",
        help="write the document but print nothing on success",
    )

    show = sub.add_parser("show", help="Summarise an analysis database.")
    show.add_argument("db", metavar="DB", help="SQLite analysis database path")
    show.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="print the summary as JSON instead of text",
    )
    diff_lane = sub.add_parser(
        "diff-import",
        help="Import a Diaphora diff export as rebase candidates.",
        description=(
            "Read a Diaphora SQLite diff export and print rebase candidates "
            "as JSON."
        ),
    )
    diff.add_arguments(diff_lane)
    return parser


def _lane_kind(args: argparse.Namespace) -> str:
    return args.kind or LANE_KINDS[args.command]


def _fail(args: argparse.Namespace, message: str) -> int:
    print(f"{PROG}: {args.command}: {message}", file=sys.stderr)
    return 1

def _summarize(path: str, report: dict) -> str:
    if report["applied"]:
        verdict = "applied"
    else:
        verdict = f"skipped ({report['skipped_reason']})"
    return (
        f"{path}: {report['kind']} {str(report.get('digest') or '?')[:12]} {verdict} — "
        f"funcs +{report.get('funcs_inserted', 0)}/~{report.get('funcs_updated', 0)}, "
        f"edges +{report.get('edges_inserted', 0)}, "
        f"labels +{report.get('labels_inserted', 0)}/~{report.get('labels_updated', 0)}"
    )


def cmd_ingest(args: argparse.Namespace) -> int:
    """Run an ingest lane; returns the process exit code."""
    kind = _lane_kind(args)
    reports: list[dict] = []

    for raw in args.documents:
        path = Path(raw)
        if not path.exists():
            return _fail(args, f"no such document: {path}")
        if args.dry_run:
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                return _fail(args, f"{path}: {exc}")
            errors = schema.validate_document(kind, document)
            if errors:
                for error in errors:
                    print(f"{path}: {error}", file=sys.stderr)
                return _fail(args, f"{path}: validation failed")
            reports.append(
                {
                    "kind": kind,
                    "path": str(path),
                    "applied": False,
                    "skipped_reason": "dry-run",
                    "digest": schema.document_digest(kind, document),
                    "errors": [],
                }
            )
            continue
        try:
            report = ingest_file(args.db, path, kind=kind, force=args.force)
        except IngestError as exc:
            return _fail(args, str(exc))
        report["path"] = str(path)
        reports.append(report)

    if args.as_json:
        print(json.dumps(reports, indent=2, sort_keys=True))
    elif not args.quiet:
        for report in reports:
            print(_summarize(report.get("path", "?"), report))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    """Print counts and provenance rows for a database."""
    db = Path(args.db)
    if not db.exists():
        return _fail(args, f"no such database: {db}")
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("funcs", "edges", "labels", "provenance")
            if table in tables
        }
        provenance = []
        if "provenance" in tables:
            provenance = [
                dict(row)
                for row in conn.execute(
                    "SELECT doc_kind, doc_id, doc_source, backend, ida_version, "
                    "auto_analysis, source_path, funcs, edges, labels, ingested_at "
                    "FROM provenance ORDER BY doc_kind, doc_id"
                )
            ]
    finally:
        conn.close()

    if args.as_json:
        print(
            json.dumps(
                {"counts": counts, "provenance": provenance},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"{db}: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        for row in provenance:
            print(
                f"  {row['doc_kind']} {str(row['doc_id'])[:12]} "
                f"source={row['doc_source']} backend={row['backend']} "
                f"ida={row['ida_version']} funcs={row['funcs']} "
                f"edges={row['edges']} labels={row['labels']}"
            )
    return 0


def _extract_module():
    """Import :mod:`icepick.extract` lazily (its IDA imports stay inside functions).

    Importing the module is IDA-free — ``idapro``/``idaapi`` are imported by
    ``import_ida()`` at run time — but keeping the import here guarantees the CLI
    front door and its parser never drag the IDA lane in at all.
    """
    from . import extract  # noqa: PLC0415 - lazy: keeps ``import icepick.cli`` IDA-free

    return extract


def cmd_extract(args: argparse.Namespace) -> int:
    """Run the extraction lane; returns the process exit code."""
    extract = _extract_module()
    if getattr(args, "top_k", None) is None:
        args.top_k = extract.DEFAULT_TOP_K
    return int(extract.main(args))


def cmd_diff_import(args: argparse.Namespace) -> int:
    """Run the diff-import lane; returns the process exit code."""
    return int(diff.main(args))


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command in LANE_KINDS:
        return cmd_ingest(args)
    if args.command == "show":
        return cmd_show(args)
    if args.command == "extract":
        return cmd_extract(args)
    if args.command == "diff-import":
        return cmd_diff_import(args)
    parser.error(f"unknown command: {args.command!r}")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
