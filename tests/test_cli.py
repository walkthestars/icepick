"""CLI smoke tests — ``ingest`` / ``ingest-manual`` subcommands through argparse."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from icepick import cli, schema
from icepick.ingest import IngestError

FIXTURE = Path(__file__).resolve().parent / "data" / "ida_extract.v1.json"


def _labels_doc() -> dict:
    return {
        "schema_version": "v1",
        "kind": "labels",
        "source": "manual",
        "generator": "cli-test",
        "labels": [
            {
                "ea": "0x140001000",
                "name": "gs_entity_alloc",
                "kind": "func",
                "prototype": "int __fastcall gs_entity_alloc(int a1, int a2)",
            },
            {"ea": "0x140004000", "name": "gs_zone_data", "kind": "data"},
        ],
    }


@pytest.fixture()
def db(tmp_path) -> Path:
    return tmp_path / "analysis.db"


def _query(db: Path, sql: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(str(db))
    try:
        return [tuple(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


# --------------------------------------------------------------------------
# parser surface
# --------------------------------------------------------------------------
def test_parser_exposes_ingest_and_ingest_manual():
    parser = cli.build_parser()
    subparsers = [
        action
        for action in parser._actions
        if action.__class__.__name__ == "_SubParsersAction"
    ]
    assert subparsers, "expected subparsers"
    choices = set(subparsers[0].choices)
    assert {"ingest", "ingest-manual"} <= choices


def test_ingest_takes_db_and_documents_positionally(capsys):
    parser = cli.build_parser()
    args = parser.parse_args(["ingest", "x.db", "a.json", "b.json"])
    assert args.db == "x.db"
    assert args.documents == ["a.json", "b.json"]
    assert args.command == "ingest"
    assert args.force is False and args.dry_run is False


def test_ingest_manual_takes_db_and_documents_positionally():
    args = cli.build_parser().parse_args(["ingest-manual", "x.db", "labels.json"])
    assert args.command == "ingest-manual"
    assert args.documents == ["labels.json"]


def test_missing_arguments_exit_with_usage():
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["ingest"])
    assert excinfo.value.code == 2


def test_no_command_exits_with_usage():
    with pytest.raises(SystemExit) as excinfo:
        cli.build_parser().parse_args([])
    assert excinfo.value.code == 2


def test_version_flag_mentions_schema_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.build_parser().parse_args(["--version"])
    assert excinfo.value.code == 0
    assert schema.SCHEMA_VERSION in capsys.readouterr().out


# --------------------------------------------------------------------------
# ingest lane
# --------------------------------------------------------------------------
def test_cli_ingest_is_green_and_populates_db(db):
    assert cli.main(["ingest", str(db), str(FIXTURE)]) == 0
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 3
    assert _query(db, "SELECT COUNT(*) FROM edges")[0][0] == 4
    assert _query(db, "SELECT DISTINCT source FROM funcs")[0][0] == "ida"


def test_cli_ingest_reports_skip_on_second_run(db, capsys):
    assert cli.main(["ingest", str(db), str(FIXTURE)]) == 0
    capsys.readouterr()
    assert cli.main(["ingest", str(db), str(FIXTURE)]) == 0
    out = capsys.readouterr().out
    assert "skipped (already-ingested)" in out


def test_cli_ingest_json_report(db, capsys):
    assert cli.main(["ingest", str(db), str(FIXTURE), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["kind"] == "extract"
    assert payload[0]["applied"] is True
    assert payload[0]["digest"] == schema.extract_digest(
        json.loads(FIXTURE.read_text("utf-8"))
    )


def test_cli_ingest_quiet_prints_nothing(db, capsys):
    assert cli.main(["ingest", str(db), str(FIXTURE), "--quiet"]) == 0
    assert capsys.readouterr().out == ""


def test_cli_dry_run_writes_nothing(db, capsys):
    assert cli.main(["ingest", str(db), str(FIXTURE), "--dry-run"]) == 0
    assert capsys.readouterr().out.strip()
    assert not db.exists()


def test_cli_missing_document_fails(db, capsys):
    assert cli.main(["ingest", str(db), "nope.json"]) == 1
    assert "no such document" in capsys.readouterr().err


def test_cli_invalid_document_fails_loudly(db, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    payload = json.loads(FIXTURE.read_text("utf-8"))
    payload["provenance"]["backend"] = "ghidra"
    bad.write_text(json.dumps(payload), encoding="utf-8")

    assert cli.main(["ingest", str(db), str(bad)]) == 1
    err = capsys.readouterr().err
    assert "backend" in err
    # nothing is written: either the database was never created (validation
    # precedes the connection) or it exists with zero function rows.
    assert not db.exists() or _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 0


def test_cli_dry_run_reports_validation_errors(db, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "v9"}), encoding="utf-8")
    assert cli.main(["ingest", str(db), str(bad), "--dry-run"]) == 1
    err = capsys.readouterr().err
    assert "schema_version" in err


def test_cli_ingest_creates_missing_parent_dirs(tmp_path):
    target = tmp_path / "nested" / "deeper" / "analysis.db"
    assert cli.main(["ingest", str(target), str(FIXTURE)]) == 0
    assert target.exists()


def test_cli_multiple_documents_in_one_call(db, tmp_path):
    second = tmp_path / "second.json"
    payload = json.loads(FIXTURE.read_text("utf-8"))
    payload["funcs"] = [
        {
            "ea": "0x140009000",
            "name": "sub_140009000",
            "size": 8,
            "blocks": 1,
            "flags": [],
            "callees": [],
            "decompiled": "int sub_140009000(void){return 0;}",
            "decompile_status": "ok",
            "decompile_error": None,
        }
    ]
    payload["edges"] = []
    second.write_text(json.dumps(payload), encoding="utf-8")

    assert cli.main(["ingest", str(db), str(FIXTURE), str(second)]) == 0
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 4


# --------------------------------------------------------------------------
# ingest-manual lane
# --------------------------------------------------------------------------
def test_cli_ingest_manual_is_green_and_tags_manual(db, tmp_path):
    path = tmp_path / "external_labels.json"
    path.write_text(json.dumps(_labels_doc()), encoding="utf-8")

    assert cli.main(["ingest-manual", str(db), str(path)]) == 0
    assert _query(db, "SELECT DISTINCT source FROM labels")[0][0] == "manual"
    assert _query(db, "SELECT name_source FROM funcs WHERE ea = ?", (0x140001000,))[0][
        0
    ] == "manual"


def test_cli_manual_then_ingest_keeps_manual_name(db, tmp_path, capsys):
    path = tmp_path / "external_labels.json"
    path.write_text(json.dumps(_labels_doc()), encoding="utf-8")

    assert cli.main(["ingest-manual", str(db), str(path)]) == 0
    assert cli.main(["ingest", str(db), str(FIXTURE)]) == 0
    capsys.readouterr()
    assert _query(db, "SELECT name FROM funcs WHERE ea = ?", (0x140001000,))[0][0] == (
        "gs_entity_alloc"
    )


def test_cli_manual_rejects_an_ida_sourced_label_doc(db, tmp_path, capsys):
    path = tmp_path / "bad_labels.json"
    payload = _labels_doc()
    payload["source"] = "ida"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert cli.main(["ingest-manual", str(db), str(path)]) == 1
    assert "manual" in capsys.readouterr().err


def test_cli_ingest_manual_dry_run(db, tmp_path):
    path = tmp_path / "external_labels.json"
    path.write_text(json.dumps(_labels_doc()), encoding="utf-8")
    assert cli.main(["ingest-manual", str(db), str(path), "--dry-run"]) == 0
    assert not db.exists()


# --------------------------------------------------------------------------
# show
# --------------------------------------------------------------------------
def test_cli_show_summarises_counts(db, capsys):
    cli.main(["ingest", str(db), str(FIXTURE)])
    capsys.readouterr()
    assert cli.main(["show", str(db)]) == 0
    out = capsys.readouterr().out
    assert "funcs=3" in out and "edges=4" in out
    assert "extract" in out


def test_cli_show_json(db, capsys):
    cli.main(["ingest", str(db), str(FIXTURE)])
    capsys.readouterr()
    assert cli.main(["show", str(db), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["funcs"] == 3
    assert payload["provenance"][0]["backend"] == "idalib"


def test_cli_show_missing_db_fails(tmp_path, capsys):
    assert cli.main(["show", str(tmp_path / "nope.db")]) == 1
    assert "no such database" in capsys.readouterr().err


# --------------------------------------------------------------------------
# module entry point
# --------------------------------------------------------------------------
def test_module_main_delegates_to_cli():
    import icepick.__main__ as entry
    from icepick import cli as cli_module

    assert entry.main is cli_module.main


def test_ingest_module_main_delegates_to_cli():
    from icepick import ingest as ingest_module

    assert callable(ingest_module.main)


def test_ingest_error_is_a_value_error():
    assert issubclass(IngestError, ValueError)
