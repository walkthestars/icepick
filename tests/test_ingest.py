"""Ingest tests — provenance, exactly-once idempotence, manual precedence."""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from icepick import ingest, schema

FIXTURE = Path(__file__).resolve().parent / "data" / "ida_extract.v1.json"


@pytest.fixture()
def extract() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture()
def labels() -> dict:
    return {
        "schema_version": "v1",
        "kind": "labels",
        "source": "manual",
        "generator": "hand-authored/gs-format-kit",
        "idb_sha256": "a" * 64,
        "labels": [
            {
                "ea": "0x140001000",
                "name": "gs_entity_alloc",
                "kind": "func",
                "prototype": "int __fastcall gs_entity_alloc(int a1, int a2)",
            },
            {"ea": "0x140003000", "name": "gs_zone_table", "kind": "func"},
            {"ea": "0x140004000", "name": "gs_zone_data", "kind": "data"},
        ],
    }


@pytest.fixture()
def db(tmp_path) -> Path:
    return tmp_path / "analysis.db"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _query(db: Path, sql: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(str(db))
    try:
        return [tuple(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _tables(db: Path) -> set[str]:
    return {
        row[0]
        for row in _query(db, "SELECT name FROM sqlite_master WHERE type='table'")
    }


# --------------------------------------------------------------------------
# table surface
# --------------------------------------------------------------------------
def test_tables_are_created(db, extract):
    report = ingest.ingest_extract(db, extract)
    assert report["applied"] is True
    tables = _tables(db)
    assert {"funcs", "edges", "provenance"} <= tables
    # labels table exists as soon as the schema is applied too
    ingest.ensure_schema(db)
    assert "labels" in _tables(db)


def test_exported_api_is_callable(db, extract, labels):
    assert callable(ingest.ingest_extract)
    assert callable(ingest.ingest_manual)
    assert callable(ingest.ensure_schema)
    assert callable(ingest.ingest_file)
    ingest.ensure_schema(db)
    assert "funcs" in _tables(db)
    ingest.ingest_extract(db, extract)
    ingest.ingest_manual(db, labels)


# --------------------------------------------------------------------------
# extract ingest
# --------------------------------------------------------------------------
def test_extract_writes_all_funcs_and_edges(db, extract):
    report = ingest.ingest_extract(db, extract)
    assert report["funcs_inserted"] == 3
    assert report["edges_inserted"] == len(extract["edges"]) == 4
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 3
    assert _query(db, "SELECT COUNT(*) FROM edges")[0][0] == 4


def test_extract_rows_are_tagged_source_ida(db, extract):
    ingest.ingest_extract(db, extract)
    sources = {row[0] for row in _query(db, "SELECT DISTINCT source FROM funcs")}
    edge_sources = {row[0] for row in _query(db, "SELECT DISTINCT source FROM edges")}
    assert sources == {"ida"}
    assert edge_sources == {"ida"}


def test_flirt_and_empty_decompile_survive_roundtrip(db, extract):
    ingest.ingest_extract(db, extract)
    rows = dict(
        (row[0], row)
        for row in _query(
            db, "SELECT ea, name, name_source, decompiled, decompile_error FROM funcs"
        )
    )
    flirt = rows[0x140002000]
    assert flirt[1] == "_strlen" and flirt[2] == "flirt"

    empty = rows[0x140003000]
    assert empty[3] is None
    assert empty[4] == "DECOMPILE_FAILED(too_big)"


def test_edges_derived_when_absent(db, tmp_path, extract):
    no_edges = copy.deepcopy(extract)
    del no_edges["edges"]
    ingest.ingest_extract(db, no_edges)
    assert _query(db, "SELECT COUNT(*) FROM edges")[0][0] == 4


def test_extract_accepts_a_path(db, extract):
    ingest.ingest_extract(db, FIXTURE)
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 3


def test_extract_rejects_invalid_document(db, extract):
    extract["provenance"]["backend"] = "ghidra"
    with pytest.raises(ingest.IngestError) as excinfo:
        ingest.ingest_extract(db, extract)
    assert "backend" in str(excinfo.value)


def test_rejected_document_writes_nothing(db, extract):
    bad = copy.deepcopy(extract)
    del bad["provenance"]
    with pytest.raises(ingest.IngestError):
        ingest.ingest_extract(db, bad)
    # validation fails before the target is ever opened, so the database
    # file is never even created (validation precedes connection open).
    assert not db.exists(), "a rejected document must not create the database"


# --------------------------------------------------------------------------
# provenance
# --------------------------------------------------------------------------
def test_provenance_row_carries_required_fields(db, extract):
    report = ingest.ingest_extract(db, extract, source_path=FIXTURE)
    rows = _query(
        db,
        "SELECT doc_kind, doc_id, schema_version, doc_source, ida_version, "
        "idb_sha256, auto_analysis, backend, source_path, funcs, edges, ingested_at "
        "FROM provenance",
    )
    assert len(rows) == 1
    (
        doc_kind,
        doc_id,
        version,
        doc_source,
        ida_version,
        idb_sha256,
        auto_analysis,
        backend,
        source_path,
        funcs,
        edges,
        ingested_at,
    ) = rows[0]
    assert doc_kind == "extract"
    assert doc_id == report["digest"] == schema.extract_digest(extract)
    assert version == schema.SCHEMA_VERSION
    assert doc_source == "ida"
    assert ida_version == extract["provenance"]["ida_version"]
    assert idb_sha256 == extract["provenance"]["idb_sha256"]
    assert auto_analysis == 1
    assert backend == "idalib"
    assert Path(source_path) == FIXTURE
    assert (funcs, edges) == (3, 4)
    assert ingested_at.endswith("+00:00")


def test_labels_provenance_is_tagged_manual(db, labels):
    ingest.ingest_manual(db, labels, source_path="external_labels.json")
    row = _query(db, "SELECT doc_kind, doc_source, generator FROM provenance")[0]
    assert row[0] == "labels"
    assert row[1] == "manual"
    assert row[2] == "hand-authored/gs-format-kit"


def test_both_lane_provenance_rows_coexist(db, extract, labels):
    ingest.ingest_extract(db, extract)
    ingest.ingest_manual(db, labels)
    kinds = sorted(row[0] for row in _query(db, "SELECT doc_kind FROM provenance"))
    assert kinds == ["extract", "labels"]


# --------------------------------------------------------------------------
# exactly-once idempotence
# --------------------------------------------------------------------------
def test_reingest_of_extract_is_byte_identical(db, extract):
    first = ingest.ingest_extract(db, extract)
    digest_before = _sha(db)
    second = ingest.ingest_extract(db, extract)

    assert first["applied"] is True
    assert second["applied"] is False
    assert second["skipped_reason"] == "already-ingested"
    assert second["digest"] == first["digest"]
    assert _sha(db) == digest_before
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 3
    assert _query(db, "SELECT COUNT(*) FROM provenance")[0][0] == 1


def test_reingest_across_reformatted_json_is_a_noop(db, extract, tmp_path):
    ingest.ingest_extract(db, extract)
    digest_before = _sha(db)

    noisy = copy.deepcopy(extract)
    noisy["funcs"] = list(reversed(noisy["funcs"]))
    for func in noisy["funcs"]:
        func["ea"] = int(func["ea"], 16)
        func["flags"] = list(reversed(func["flags"]))
    reordered = tmp_path / "reordered.json"
    reordered.write_text(json.dumps(noisy, indent=4), encoding="utf-8")

    report = ingest.ingest_extract(db, reordered)
    assert report["applied"] is False
    assert _sha(db) == digest_before
    assert _query(db, "SELECT COUNT(*) FROM provenance")[0][0] == 1


def test_reingest_is_stable_over_many_runs(db, extract):
    ingest.ingest_extract(db, extract)
    digest_before = _sha(db)
    for _ in range(5):
        assert ingest.ingest_extract(db, extract)["applied"] is False
    assert _sha(db) == digest_before


def test_reingest_of_manual_is_byte_identical(db, labels):
    ingest.ingest_manual(db, labels)
    digest_before = _sha(db)
    again = ingest.ingest_manual(db, labels)
    assert again["applied"] is False
    assert again["skipped_reason"] == "already-ingested"
    assert _sha(db) == digest_before
    assert _query(db, "SELECT COUNT(*) FROM labels")[0][0] == 3


def test_force_reapplies_without_duplicating(db, extract):
    ingest.ingest_extract(db, extract)
    forced = ingest.ingest_extract(db, extract, force=True)
    assert forced["applied"] is True
    assert forced["funcs_unchanged"] == 3
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 3
    assert _query(db, "SELECT COUNT(*) FROM edges")[0][0] == 4


def test_changed_content_is_a_new_document(db, extract):
    ingest.ingest_extract(db, extract)
    changed = copy.deepcopy(extract)
    changed["funcs"][0]["name"] = "sub_renamed"
    report = ingest.ingest_extract(db, changed)
    assert report["applied"] is True
    assert report["funcs_updated"] == 1
    assert len(_query(db, "SELECT doc_id FROM provenance")) == 2
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 3
    assert _query(db, "SELECT name FROM funcs WHERE ea = ?", (0x140001000,))[0][0] == (
        "sub_renamed"
    )


# --------------------------------------------------------------------------
# manual precedence
# --------------------------------------------------------------------------
def test_manual_labels_land_in_labels_table_as_manual(db, labels):
    ingest.ingest_manual(db, labels)
    sources = {row[0] for row in _query(db, "SELECT DISTINCT source FROM labels")}
    assert sources == {"manual"}
    assert _query(db, "SELECT COUNT(*) FROM labels")[0][0] == 3


def test_manual_name_outranks_ida_name(db, extract, labels):
    ingest.ingest_extract(db, extract)
    assert _query(db, "SELECT name FROM funcs WHERE ea = ?", (0x140001000,))[0][0] == (
        "sub_140001000"
    )

    ingest.ingest_manual(db, labels)
    row = _query(
        db, "SELECT name, name_source, name_rank FROM funcs WHERE ea = ?", (0x140001000,)
    )[0]
    assert row == ("gs_entity_alloc", "manual", ingest.NAME_SOURCE_RANK["manual"])


def test_ida_reingest_cannot_overwrite_manual_name(db, extract, labels):
    ingest.ingest_manual(db, labels)
    report = ingest.ingest_extract(db, extract)
    row = _query(
        db, "SELECT name, name_source FROM funcs WHERE ea = ?", (0x140001000,)
    )[0]
    assert row == ("gs_entity_alloc", "manual")
    assert any(c["ea"] == 0x140001000 for c in report["name_precedence_collisions"])
    assert _query(db, "SELECT name FROM funcs WHERE ea = ?", (0x140002000,))[0][0] == (
        "_strlen"
    )


def test_manual_overrides_flirt_name_too(db, extract, labels):
    labels = copy.deepcopy(labels)
    labels["labels"] = [
        {"ea": "0x140002000", "name": "gs_strlen_impl", "kind": "func"}
    ]
    ingest.ingest_extract(db, extract)
    ingest.ingest_manual(db, labels)
    assert _query(db, "SELECT name FROM funcs WHERE ea = ?", (0x140002000,))[0][0] == (
        "gs_strlen_impl"
    )


def test_manual_func_for_unknown_ea_creates_a_row(db, labels):
    ingest.ingest_manual(db, labels)
    row = _query(
        db,
        "SELECT name, name_source, source FROM funcs WHERE ea = ?",
        (0x140003000,),
    )[0]
    assert row == ("gs_zone_table", "manual", "manual")


def test_data_labels_stay_out_of_funcs(db, labels):
    ingest.ingest_manual(db, labels)
    assert _query(db, "SELECT COUNT(*) FROM funcs WHERE ea = ?", (0x140004000,))[0][
        0
    ] == 0
    kinds = {row[0] for row in _query(db, "SELECT DISTINCT kind FROM labels")}
    assert kinds == {"func", "data"}


def test_manual_labels_do_not_touch_edges(db, extract, labels):
    ingest.ingest_extract(db, extract)
    before = _query(db, "SELECT COUNT(*) FROM edges")[0][0]
    ingest.ingest_manual(db, labels)
    assert _query(db, "SELECT COUNT(*) FROM edges")[0][0] == before


def test_dynamic_receipts_still_outrank_manual(db, extract, labels):
    ingest.ingest_manual(db, labels)
    ingest.ingest_extract(db, extract)
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "UPDATE funcs SET name = ?, name_source = ?, name_rank = ? WHERE ea = ?",
            ("gs_entity_alloc_dyn", "dyn", ingest.NAME_SOURCE_RANK["dyn"], 0x140001000),
        )
        conn.commit()
    finally:
        conn.close()
    report = ingest.ingest_extract(db, extract)
    assert report["applied"] is False or report["funcs_updated"] == 0
    assert _query(db, "SELECT name FROM funcs WHERE ea = ?", (0x140001000,))[0][0] == (
        "gs_entity_alloc_dyn"
    )


# --------------------------------------------------------------------------
# file / connection conveniences
# --------------------------------------------------------------------------
def test_ingest_file_infers_kind(db, extract, labels, tmp_path):
    extract_path = tmp_path / "extract.json"
    extract_path.write_text(json.dumps(extract), encoding="utf-8")
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps(labels), encoding="utf-8")

    assert ingest.ingest_file(db, extract_path)["kind"] == "extract"
    assert ingest.ingest_file(db, labels_path)["kind"] == "labels"
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 3
    assert _query(db, "SELECT COUNT(*) FROM labels")[0][0] == 3


def test_ingest_file_rejects_missing_document(db):
    with pytest.raises(ingest.IngestError):
        ingest.ingest_file(db, "does-not-exist.json")


def test_ingest_accepts_an_open_connection(tmp_path, extract):
    conn = sqlite3.connect(":memory:")
    try:
        report = ingest.ingest_extract(conn, extract)
        assert report["applied"] is True
        assert conn.execute("SELECT COUNT(*) FROM funcs").fetchone()[0] == 3
        assert report["skipped_reason"] is None
        again = ingest.ingest_extract(conn, extract)
        assert again["applied"] is False
    finally:
        conn.close()


def test_ingest_many_in_deterministic_order(db, extract, labels, tmp_path):
    paths = []
    for name, doc in (("a.json", labels), ("b.json", extract)):
        path = tmp_path / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        paths.append(path)
    reports = ingest.ingest_many(db, paths)
    assert [r["kind"] for r in reports] == ["labels", "extract"]
    assert _query(db, "SELECT COUNT(*) FROM funcs")[0][0] == 3


def test_canonical_digest_matches_schema(db, extract, labels):
    assert ingest.canonical_digest("extract", extract) == schema.extract_digest(extract)
    assert ingest.canonical_digest("labels", labels) == schema.labels_digest(labels)


def test_invalid_target_is_rejected(extract):
    with pytest.raises(ingest.IngestError):
        ingest.ingest_extract(42, extract)
