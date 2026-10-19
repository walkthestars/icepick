"""Diaphora import tests — synthetic SQLite exports, zero IDA runtime.

The exports here are hand-built to the column aliases
:mod:`icepick.diff` understands (``functions`` + ``results`` tables); no real
Diaphora install is involved.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from icepick import cli, diff


def _synthetic_export(
    path: Path,
    *,
    with_results: bool = True,
    with_names: bool = True,
    second_ratio: float = 0.2,
) -> Path:
    conn = sqlite3.connect(str(path))
    if with_names:
        conn.execute(
            "CREATE TABLE functions (address INTEGER, name TEXT, "
            "pseudocode_hash TEXT, pseudocode TEXT, size INTEGER)"
        )
    if with_names:
        conn.execute(
            "INSERT INTO functions VALUES (0x1000, 'sub_1000', 'aaa', 'int f();', 10)"
        )
        conn.execute(
            "INSERT INTO functions VALUES (0x2000, 'sub_2000', 'bbb', 'void g();', 20)"
        )
    else:
        conn.execute(
            "CREATE TABLE functions (address INTEGER, "
            "pseudocode_hash TEXT, pseudocode TEXT, size INTEGER)"
        )
        conn.execute("INSERT INTO functions VALUES (0x1000, 'aaa', 'int f();', 10)")
    if with_results:
        conn.execute(
            "CREATE TABLE results (address INTEGER, address2 INTEGER, "
            "similarity REAL, name1 TEXT, name2 TEXT, "
            "pseudocode_hash1 TEXT, pseudocode_hash2 TEXT)"
        )
        conn.execute(
            "INSERT INTO results VALUES "
            "(0x1000, 0x5000, 0.97, 'sub_1000', 'sub_1000', 'aaa', 'aaa')"
        )
        conn.execute(
            "INSERT INTO results VALUES "
            f"(0x2000, 0x6000, {second_ratio}, 'sub_2000', 'other', 'bbb', 'ccc')"
        )
    conn.commit()
    conn.close()
    return path


def test_read_synthetic_export(tmp_path: Path) -> None:
    db = _synthetic_export(tmp_path / "diff.sqlite")
    report = diff.read_diaphora(db)
    assert len(report.functions) == 2
    assert len(report.results) == 2

    candidates = diff.to_rebase_candidates(report)
    assert len(candidates) == 2
    best = candidates[0]
    assert (best["old_ea"], best["new_ea"]) == (0x1000, 0x5000)
    assert best["score"] == 1.0
    assert best["signals"]["name_equal"] is True
    assert best["signals"]["pseudocode_hash_equal"] is True
    second = candidates[1]
    assert second["signals"]["name_equal"] is False
    assert second["signals"]["pseudocode_hash_equal"] is False
    assert 0.0 <= second["score"] < best["score"]


def test_min_score_and_limit_filter(tmp_path: Path) -> None:
    db = _synthetic_export(tmp_path / "diff.sqlite")
    report = diff.read_diaphora(db)
    assert len(diff.to_rebase_candidates(report, min_score=0.5)) == 1
    assert len(diff.to_rebase_candidates(report, limit=1)) == 1
    assert diff.to_rebase_candidates(report, limit=1)[0]["old_ea"] == 0x1000


def test_missing_results_table_raises(tmp_path: Path) -> None:
    db = _synthetic_export(tmp_path / "diff.sqlite", with_results=False)
    with pytest.raises(diff.DiffError, match="results"):
        diff.read_diaphora(db)


def test_missing_name_column_raises(tmp_path: Path) -> None:
    db = _synthetic_export(tmp_path / "diff.sqlite", with_names=False)
    with pytest.raises(diff.DiffError, match="[Nn]ame"):
        diff.read_diaphora(db)


def test_not_sqlite_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.sqlite"
    bad.write_text("not a database", encoding="utf-8")
    with pytest.raises(diff.DiffError):
        diff.read_diaphora(bad)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(diff.DiffError, match="no such"):
        diff.read_diaphora(tmp_path / "absent.sqlite")


def test_cli_diff_import(tmp_path: Path) -> None:
    db = _synthetic_export(tmp_path / "diff.sqlite")
    out = tmp_path / "candidates.json"
    assert cli.main(["diff-import", str(db), "--out", str(out)]) == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["counts"]["candidates"] == 2
    assert document["candidates"][0]["old_ea"] == 0x1000
