"""Schema tests — good/bad coverage for ``validate_extract`` / ``validate_labels``."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from icepick import schema

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
        "labels": [
            {
                "ea": "0x140001000",
                "name": "gs_entity_alloc",
                "kind": "func",
                "prototype": "int __fastcall gs_entity_alloc(int a1, int a2)",
                "note": "FastFile entity allocator",
            },
            {"ea": "0x140003000", "name": "gs_zone_table", "kind": "data"},
        ],
    }


# --------------------------------------------------------------------------
# module surface
# --------------------------------------------------------------------------
def test_schema_version_is_v1():
    assert schema.SCHEMA_VERSION == "v1"


def test_validate_functions_return_error_lists():
    assert schema.validate_extract({}) != []
    assert schema.validate_labels({}) != []
    assert isinstance(schema.validate_extract({}), list)
    assert isinstance(schema.validate_labels({}), list)
    assert all(isinstance(e, str) for e in schema.validate_extract({}))


def test_validate_never_raises_on_garbage():
    for garbage in (None, 5, "x", [], {"funcs": 3}, {"labels": object()}):
        assert isinstance(schema.validate_extract(garbage), list)
        assert isinstance(schema.validate_labels(garbage), list)


# --------------------------------------------------------------------------
# fixture shape (the golden document itself)
# --------------------------------------------------------------------------
def test_fixture_has_three_funcs_with_expected_flavours(extract):
    funcs = extract["funcs"]
    assert len(funcs) == 3

    normal = funcs[0]
    assert normal["name_source"] == "ida"
    assert normal["decompiled"] and normal["decompile_status"] == "ok"

    flirt = funcs[1]
    assert flirt["name"] == "_strlen" and flirt["name_source"] == "flirt"
    assert "library" in flirt["flags"]

    empty = funcs[2]
    assert empty["decompiled"] is None
    assert empty["decompile_status"] == "failed"
    assert empty["decompile_error"].startswith("DECOMPILE_FAILED(")


def test_fixture_is_valid_and_has_no_errors(extract):
    assert schema.validate_extract(extract) == []


def test_sigs_applied_absent_and_well_formed_validate(extract):
    assert schema.validate_extract(extract) == []
    extract["provenance"]["sigs_applied"] = [
        {"name": "iw8-1.0.sig"},
        {"name": "common.sig", "version": "3", "sha": None},
    ]
    assert schema.validate_extract(extract) == []


def test_sigs_applied_rejects_malformed_entries(extract):
    extract["provenance"]["sigs_applied"] = [{"version": "3"}]
    assert any("sigs_applied" in e for e in schema.validate_extract(extract))
    extract["provenance"]["sigs_applied"] = "iw8.sig"
    assert any("sigs_applied" in e for e in schema.validate_extract(extract))


@pytest.mark.parametrize("status", ["ok", "too_big", "timeout", "failed"])
def test_all_decompile_statuses_validate(extract, status):
    func = extract["funcs"][0]
    if status == "ok":
        func["decompiled"] = "int f();"
        func["decompile_error"] = None
    else:
        func["decompiled"] = None
        func["decompile_error"] = f"DECOMPILE_FAILED({status})"
    func["decompile_status"] = status
    assert schema.validate_extract(extract) == []


def test_fixture_provenance_has_required_fields(extract):
    prov = extract["provenance"]
    for key in ("ida_version", "idb_sha256", "auto_analysis", "backend"):
        assert key in prov, f"provenance missing {key}"
    assert prov["backend"] in schema.BACKENDS
    assert isinstance(prov["auto_analysis"], bool)
    assert len(prov["idb_sha256"]) == 64


# --------------------------------------------------------------------------
# extract: rejections
# --------------------------------------------------------------------------
def test_wrong_schema_version_is_reported(extract):
    extract["schema_version"] = "v2"
    assert any("schema_version" in e for e in schema.validate_extract(extract))


def test_missing_schema_version_is_reported(extract):
    del extract["schema_version"]
    assert any("schema_version" in e for e in schema.validate_extract(extract))


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda d: d["provenance"].pop("ida_version"), id="no-ida_version"),
        pytest.param(lambda d: d["provenance"].pop("idb_sha256"), id="no-idb_sha256"),
        pytest.param(
            lambda d: d["provenance"].pop("auto_analysis"), id="no-auto_analysis"
        ),
        pytest.param(lambda d: d["provenance"].pop("backend"), id="no-backend"),
        pytest.param(lambda d: d.pop("provenance"), id="no-provenance-block"),
    ],
)
def test_provenance_fields_are_required(extract, mutation):
    mutation(extract)
    errors = schema.validate_extract(extract)
    assert errors, f"expected errors, got {errors}"
    assert any("provenance" in e for e in errors)


def test_bad_backend_is_rejected(extract):
    extract["provenance"]["backend"] = "ghidra"
    assert any("backend" in e for e in schema.validate_extract(extract))


def test_bad_idb_sha_is_rejected(extract):
    extract["provenance"]["idb_sha256"] = "not-a-sha"
    assert any("idb_sha256" in e for e in schema.validate_extract(extract))


def test_auto_analysis_must_be_bool(extract):
    extract["provenance"]["auto_analysis"] = "yes"
    assert any("auto_analysis" in e for e in schema.validate_extract(extract))


def test_duplicate_func_ea_is_rejected(extract):
    extract["funcs"].append(copy.deepcopy(extract["funcs"][0]))
    assert any("duplicate" in e for e in schema.validate_extract(extract))


def test_bad_ea_spelling_is_rejected(extract):
    extract["funcs"][0]["ea"] = "4096"  # ambiguous decimal string
    assert any("effective address" in e for e in schema.validate_extract(extract))


def test_whitespace_in_name_is_rejected(extract):
    extract["funcs"][0]["name"] = "sub 1000"
    assert any("whitespace" in e for e in schema.validate_extract(extract))


def test_unknown_name_source_is_rejected(extract):
    extract["funcs"][0]["name_source"] = "vibes"
    assert any("name_source" in e for e in schema.validate_extract(extract))


def test_failed_decompile_needs_sentinel(extract):
    extract["funcs"][2]["decompile_error"] = "oops"
    assert any("DECOMPILE_FAILED" in e for e in schema.validate_extract(extract))


def test_decompiled_text_with_failed_status_is_contradictory(extract):
    extract["funcs"][2]["decompiled"] = "int x(void){return 1;}"
    assert any("decompiled" in e for e in schema.validate_extract(extract))


def test_bad_edge_kind_is_rejected(extract):
    extract["edges"][0]["kind"] = "teleport"
    assert any("kind" in e for e in schema.validate_extract(extract))


def test_duplicate_edge_is_rejected(extract):
    extract["edges"].append(copy.deepcopy(extract["edges"][0]))
    assert any("duplicate edge" in e for e in schema.validate_extract(extract))


def test_empty_funcs_is_rejected(extract):
    extract["funcs"] = []
    assert any("at least one" in e for e in schema.validate_extract(extract))


# --------------------------------------------------------------------------
# extract: additive-only tolerance
# --------------------------------------------------------------------------
def test_unknown_keys_are_tolerated(extract):
    extract["future_block"] = {"whatever": 1}
    extract["funcs"][0]["future_field"] = [1, 2, 3]
    assert schema.validate_extract(extract) == []


def test_edges_may_be_omitted_and_derived_from_callees(extract):
    del extract["edges"]
    assert schema.validate_extract(extract) == []
    derived = schema.collect_edges(extract)
    assert derived == schema.collect_edges(json.loads(FIXTURE.read_text("utf-8")))


# --------------------------------------------------------------------------
# labels
# --------------------------------------------------------------------------
def test_valid_labels_document(labels):
    assert schema.validate_labels(labels) == []


def test_labels_must_be_manual(labels):
    labels["source"] = "ida"
    assert any("manual" in e for e in schema.validate_labels(labels))


def test_labels_require_at_least_one_entry(labels):
    labels["labels"] = []
    assert any("at least one" in e for e in schema.validate_labels(labels))


def test_label_needs_valid_kind(labels):
    labels["labels"][0]["kind"] = "sneaky"
    assert any("kind" in e for e in schema.validate_labels(labels))


def test_label_needs_valid_ea(labels):
    labels["labels"][0]["ea"] = "nope"
    assert any("effective address" in e for e in schema.validate_labels(labels))


def test_label_needs_name(labels):
    del labels["labels"][0]["name"]
    assert any("name" in e for e in schema.validate_labels(labels))


def test_duplicate_label_kind_pair_is_rejected(labels):
    labels["labels"].append(copy.deepcopy(labels["labels"][1]))
    assert any("duplicate label" in e for e in schema.validate_labels(labels))


def test_same_ea_with_different_kinds_is_allowed(labels):
    labels["labels"].append({"ea": "0x140001000", "name": "gs_x", "kind": "data"})
    assert schema.validate_labels(labels) == []


def test_bad_idb_sha_in_labels_is_rejected(labels):
    labels["idb_sha256"] = "zzz"
    assert any("idb_sha256" in e for e in schema.validate_labels(labels))


def test_validate_document_dispatch(extract, labels):
    assert schema.validate_document("extract", extract) == []
    assert schema.validate_document("labels", labels) == []
    with pytest.raises(ValueError):
        schema.validate_document("nonsense", {})


# --------------------------------------------------------------------------
# canonicalisation / digests — the substrate of exactly-once ingest
# --------------------------------------------------------------------------
def test_digest_is_order_and_format_insensitive(extract):
    shuffled = copy.deepcopy(extract)
    shuffled["funcs"] = list(reversed(shuffled["funcs"]))
    shuffled["edges"] = list(reversed(shuffled["edges"]))
    shuffled["funcs"][0]["flags"] = list(reversed(shuffled["funcs"][0]["flags"]))
    # address as int instead of hex string, key order irrelevant in JSON
    for func in shuffled["funcs"]:
        func["ea"] = int(func["ea"], 16)
    assert schema.extract_digest(shuffled) == schema.extract_digest(extract)


def test_digest_changes_when_content_changes(extract):
    changed = copy.deepcopy(extract)
    changed["funcs"][0]["name"] = "renamed"
    assert schema.extract_digest(changed) != schema.extract_digest(extract)


def test_labels_digest_is_stable_across_order(labels):
    shuffled = copy.deepcopy(labels)
    shuffled["labels"] = list(reversed(shuffled["labels"]))
    assert schema.labels_digest(shuffled) == schema.labels_digest(labels)


def test_normalization_sorts_and_types(extract):
    normalized = schema.normalize_extract(extract)
    assert [f["ea"] for f in normalized["funcs"]] == sorted(
        f["ea"] for f in normalized["funcs"]
    )
    assert isinstance(normalized["funcs"][0]["ea"], int)
    assert normalized["provenance"]["auto_analysis"] is True
    assert all(isinstance(edge["src"], int) for edge in normalized["edges"])


def test_load_and_validate_returns_errors_for_path(tmp_path, extract):
    good = tmp_path / "ok.json"
    good.write_text(json.dumps(extract), encoding="utf-8")
    obj, errors = schema.load_and_validate("extract", good)
    assert errors == [] and obj == extract

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "v1"}), encoding="utf-8")
    _, errors = schema.load_and_validate("extract", bad)
    assert errors
