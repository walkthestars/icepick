"""Trim tests — pure, no IDA runtime, no IDA import anywhere.

The fence U-IDA6 asks for is exactly the part of the live lane that can be
proved offline: ``truncate_text`` two-axis boundaries, unicode-safety of a cut,
``cap_sequence`` top-K, and the caps on a candidate card (bounded decompile /
pseudocode, named truncation, JSON-safe primitives).  Everything here calls the
pure helpers only — nothing in this file (or in :mod:`icepick.trim`) touches an
IDA module, so it runs in CI on a machine with no IDA installed at all.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from icepick import trim

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


# ---------------------------------------------------------------------------
# helpers under test stay pure and IDA-free
# ---------------------------------------------------------------------------
def test_trim_module_imports_no_ida_and_only_stdlib():
    """The fence module must never drag IDA (or a third-party dep) in."""
    text = (SRC / "icepick" / "trim.py").read_text(encoding="utf-8")
    assert "idaapi" not in text
    assert "idapro" not in text
    assert "import ida" not in text
    leaked = sorted(
        name
        for name in sys.modules
        if name.split(".")[0] in {"idapro", "idaapi", "idc", "idautils", "ida_hexrays"}
    )
    assert not leaked, f"IDA modules leaked while importing icepick.trim: {leaked}"


def test_documented_defaults_match_the_skill_fence():
    """The skills quote these numbers; changing one must break a test."""
    assert trim.DEFAULT_MAX_LINES == 200
    assert trim.DEFAULT_MAX_CHARS == 8000
    assert trim.DEFAULT_MAX_ITEMS == 50
    assert trim.DEFAULT_MAX_NAME_CHARS == 120
    extract_skill = (ROOT / "skills" / "ida-extract.md").read_text(encoding="utf-8")
    assert f"MAX_LINES = {trim.DEFAULT_MAX_LINES}" in extract_skill
    assert f"MAX_CHARS = {trim.DEFAULT_MAX_CHARS}" in extract_skill


# ---------------------------------------------------------------------------
# truncate_text — boundaries on both axes
# ---------------------------------------------------------------------------
def test_truncate_text_disabled_axes_return_input_unchanged():
    text = "a\r\nb\rc\nd"
    assert trim.truncate_text(text, None, None) == ("a\nb\nc\nd", False)


def test_truncate_text_under_the_cap_is_not_truncated():
    text = "one\ntwo\nthree"
    assert trim.truncate_text(text, 10, 100) == (text, False)


def test_truncate_text_exactly_at_the_cap_is_not_truncated():
    text = "\n".join(f"line{i}" for i in range(5))
    assert len(text.splitlines()) == 5
    assert trim.truncate_text(text, 5, None) == (text, False)
    assert trim.truncate_text(text, 5, len(text)) == (text, False)


def test_truncate_text_one_past_the_line_cap_cuts_and_reports():
    text = "\n".join(f"line{i}" for i in range(5))
    kept, truncated = trim.truncate_text(text, 4, None)
    assert truncated is True
    assert kept == "\n".join(f"line{i}" for i in range(4))
    assert kept.splitlines()[-1] == "line3"


def test_truncate_text_one_past_the_char_cap_cuts_and_reports():
    text = "x" * 11
    kept, truncated = trim.truncate_text(text, None, 10)
    assert (kept, truncated) == ("x" * 10, True)


def test_truncate_text_never_exceeds_max_chars_with_a_marker():
    text = "y" * 500
    kept, truncated = trim.truncate_text(text, None, 10, marker=trim.TRUNCATION_MARK)
    assert truncated is True
    assert len(kept) <= 10
    assert kept.endswith(trim.TRUNCATION_MARK)


def test_truncate_text_lines_apply_before_chars():
    """Line cap first, then the char cap — the order is part of the contract."""
    text = "\n".join("abcdefghij" for _ in range(10))
    kept, truncated = trim.truncate_text(text, 2, 15)
    assert truncated is True
    assert len(kept) <= 15
    assert kept.startswith("abcdefghij")


def test_truncate_text_crlf_is_normalised_but_not_truncation():
    kept, truncated = trim.truncate_text("a\r\nb\r\nc", 10, 100)
    assert kept == "a\nb\nc"
    assert truncated is False


def test_truncate_text_crlf_normalisation_keeps_the_line_budget_honest():
    # Counted with splitlines this is 3 lines; a naive count('\n') would see 1.
    text = "a\r\nb\r\nc"
    kept, truncated = trim.truncate_text(text, 2, None)
    assert truncated is True
    assert kept == "a\nb"


def test_truncate_text_none_is_the_empty_string():
    assert trim.truncate_text(None) == ("", False)
    assert trim.truncate_text(None, None, None) == ("", False)


def test_truncate_text_rejects_bad_caps():
    with pytest.raises(TypeError):
        trim.truncate_text("x", "200", 10)
    with pytest.raises(ValueError):
        trim.truncate_text("x", 0, 10)
    with pytest.raises(ValueError):
        trim.truncate_text("x", 10, 0)
    with pytest.raises(TypeError):
        trim.truncate_text("x", True, 10)
    with pytest.raises(TypeError):
        trim.truncate_text(123)


def test_truncate_text_bool_is_rejected_as_a_cap_not_silently_used():
    with pytest.raises(TypeError):
        trim.truncate_text("x" * 5, None, False)


# ---------------------------------------------------------------------------
# unicode safety — a cut never splits a grapheme or a surrogate pair
# ---------------------------------------------------------------------------
def test_safe_cut_never_splits_a_surrogate_pair():
    # U+1F600 as explicit surrogates: a cut between them must back off by one.
    text = "a" * 5 + "\ud83d\ude00" + "b" * 5
    cut = trim.safe_cut(text, 6)
    assert cut == "a" * 5
    assert not any(0xD800 <= ord(ch) <= 0xDBFF for ch in cut)


def test_truncate_text_is_surrogate_safe_at_the_boundary():
    text = "\ud83d\ude00" * 5
    kept, truncated = trim.truncate_text(text, None, 3)
    assert truncated is True
    assert len(kept) <= 3
    assert kept == "\ud83d\ude00"


def test_safe_cut_keeps_combining_marks_with_their_base():
    # "e" + COMBINING ACUTE ACCENT: the mark must not start the kept text.
    text = "x" * 4 + "e\u0301" + "y" * 4
    cut = trim.safe_cut(text, 5)
    assert cut == "x" * 4  # the mark at index 4 was dropped with its base
    assert unicodedata_safe(cut)


def unicodedata_safe(text: str) -> bool:
    """A kept prefix must not end on a combining mark, joiner or selector."""
    import unicodedata

    if not text:
        return True
    last = text[-1]
    if unicodedata.combining(last):
        return False
    if last in trim.JOINER_CHARS:
        return False
    return True


def test_safe_cut_does_not_strand_a_zwj_emoji_sequence():
    family = "\U0001f468\u200d\U0001f469\u200d\U0001f467"
    cut = trim.safe_cut(family, 2)
    assert not cut.endswith("\u200d")
    assert cut == "\U0001f468"


def test_safe_cut_does_not_strand_a_variation_selector():
    text = "\u2764\ufe0f" * 3
    cut = trim.safe_cut(text, 1)
    assert cut == "" or not cut.endswith("\ufe0f")


def test_truncate_text_unicode_content_larger_than_the_cap_stays_decodable():
    payload = ("caf\u00e9 \u4e2d\u6587 \U0001f680\n" * 40)
    kept, truncated = trim.truncate_text(payload, 10, 60, marker=trim.TRUNCATION_MARK)
    assert truncated is True
    assert len(kept) <= 60
    assert kept.encode("utf-8").decode("utf-8")  # round-trips: no split code point


def test_truncate_chars_is_the_single_axis_form():
    kept, truncated = trim.truncate_chars("abcdef", 3)
    assert (kept, truncated) == ("abc", True)
    assert trim.truncate_chars("abc", 3) == ("abc", False)


def test_truncate_lines_trailing_newline_does_not_invent_a_line():
    text = "a\nb\n"
    assert text.splitlines() == ["a", "b"]
    assert trim.truncate_lines(text, 2) == (text, False)
    assert trim.truncate_lines(text, 1) == ("a", True)


def test_normalize_newlines_handles_old_mac_and_windows():
    assert trim.normalize_newlines("a\rb\r\nc\n") == "a\nb\nc\n"
    with pytest.raises(TypeError):
        trim.normalize_newlines(None)


def test_one_line_collapses_and_caps():
    assert trim.one_line("  a\n\tb  ") == "a b"
    assert trim.one_line(None) == ""
    assert trim.one_line(12345) == "12345"
    assert len(trim.one_line("z" * 500, max_chars=7)) == 7


# ---------------------------------------------------------------------------
# cap_sequence — top-K
# ---------------------------------------------------------------------------
def test_cap_sequence_under_and_at_the_limit():
    assert trim.cap_sequence([1, 2, 3], 3) == ([1, 2, 3], False)
    assert trim.cap_sequence([1, 2, 3], 5) == ([1, 2, 3], False)


def test_cap_sequence_cuts_one_past_the_limit_and_reports():
    kept, truncated = trim.cap_sequence([1, 2, 3], 2)
    assert kept == [1, 2]
    assert truncated is True


def test_cap_sequence_none_keeps_everything_without_touching_the_sources():
    source = [1, 2, 3]
    kept, truncated = trim.cap_sequence(source, None)
    assert (kept, truncated) == ([1, 2, 3], False)
    assert kept is not source  # a copy: callers may mutate the result freely
    assert trim.cap_sequence(iter([1, 2, 3]), None) == ([1, 2, 3], False)


def test_cap_sequence_rejects_bad_limits():
    with pytest.raises(ValueError):
        trim.cap_sequence([1], 0)
    with pytest.raises(TypeError):
        trim.cap_sequence([1], "2")


# ---------------------------------------------------------------------------
# candidate_card — IDs, not blobs
# ---------------------------------------------------------------------------
def _candidate(**overrides):
    base = {
        "old_ea": 0x401000,
        "new_ea": 0x140001200,
        "score": 0.97,
        "old_name": "sub_401000",
        "new_name": "sub_140001200",
        "signals": {
            "name_equal": True,
            "pseudocode_hash_equal": False,
            "ratio": 0.97,
            "address_shift": 0x140001200 - 0x401000,
        },
    }
    base.update(overrides)
    return base


def test_card_carries_ids_and_names_not_blobs():
    card = trim.candidate_card(_candidate())
    assert card["id"] == "ea-401000-140001200"
    assert card["old_ea"] == 0x401000
    assert card["new_ea"] == 0x140001200
    assert card["old_name"] == "sub_401000"
    assert card["new_name"] == "sub_140001200"
    assert card["score"] == 0.97
    assert card["address_shift"] == 0x140001200 - 0x401000


def test_card_id_prefers_an_explicit_id_and_is_deterministic_otherwise():
    assert trim.candidate_card(_candidate(id="C-7"))["id"] == "C-7"
    first = trim.candidate_card({"decompile": "int f(void) {}"})["id"]
    second = trim.candidate_card({"decompile": "int f(void) {}"})["id"]
    assert first == second
    assert first.startswith("c")


def test_card_id_does_not_depend_on_key_order():
    one = trim.candidate_card({"a": 1, "b": 2})
    two = trim.candidate_card({"b": 2, "a": 1})
    assert one["id"] == two["id"]


def test_card_caps_decompile_text_and_names_the_cut():
    blob = "\n".join(f"line{i}" for i in range(500))
    card = trim.candidate_card(_candidate(decompile=blob))
    assert card["truncated"] == ["decompile"]
    assert card["decompile"].count("\n") < trim.DEFAULT_MAX_LINES
    assert len(card["decompile"]) <= trim.DEFAULT_MAX_CHARS
    assert card["counts"]["decompile"]["lines"] == 500


def test_card_caps_pseudocode_and_chars_independently():
    blob = "z" * 50_000
    card = trim.candidate_card(_candidate(pseudocode=blob), max_lines=None, max_chars=100)
    assert card["truncated"] == ["pseudocode"]
    assert len(card["pseudocode"]) <= 100
    assert card["counts"]["pseudocode"]["chars"] == 50_000


def test_card_short_blob_is_not_marked_truncated():
    card = trim.candidate_card(_candidate(decompile="int f(void) {\n  return 0;\n}"))
    assert card["truncated"] == []
    assert card["decompile"].startswith("int f(void)")
    assert card["counts"]["decompile"]["lines"] == 3


def test_card_truncated_order_is_fixed_not_dict_order():
    blob = "\n".join("x" for _ in range(400))
    card = trim.candidate_card(
        _candidate(pseudocode=blob, decompile=blob), max_lines=10, max_chars=None
    )
    assert card["truncated"] == ["decompile", "pseudocode"]


def test_card_drops_nested_signals_by_name():
    card = trim.candidate_card(
        _candidate(signals={"name_equal": True, "blob": {"huge": [1, 2, 3]}})
    )
    assert "blob" not in card["signals"]
    assert card["omitted_signals"] == ["blob"]
    assert card["signals"]["name_equal"] is True


def test_card_drops_non_finite_floats():
    card = trim.candidate_card(
        _candidate(score=float("nan"), signals={"ratio": float("inf")})
    )
    assert card["score"] is None
    assert card["ratio"] is None
    assert json.dumps(card, allow_nan=False)


def test_card_is_json_safe_primitives_only():
    card = trim.candidate_card(_candidate(decompile="int f(void) {}"))
    text = json.dumps(card, sort_keys=True, allow_nan=False)
    assert json.loads(text)["id"] == card["id"]
    for value in card.values():
        assert isinstance(value, (str, int, float, bool, list, dict)) or value is None


def test_card_accepts_address_strings_and_detail_mapping():
    card = trim.candidate_card(
        {
            "old_ea": "0x401000",
            "new_ea": "0x140001200",
            "details": {"name1": "old_sym", "name2": "new_sym"},
        }
    )
    assert card["id"] == "ea-401000-140001200"
    assert card["old_name"] == "old_sym"
    assert card["new_name"] == "new_sym"


def test_card_missing_text_is_empty_not_invented():
    card = trim.candidate_card({"old_ea": 1, "new_ea": 2})
    assert card["decompile"] == ""
    assert card["pseudocode"] == ""
    assert card["counts"]["decompile"] == {"lines": 0, "chars": 0}
    assert card["truncated"] == []


def test_card_names_are_collapsed_to_one_line_and_capped():
    card = trim.candidate_card(
        _candidate(old_name="a\n\tb  c", new_name="n" * 400), max_name_chars=20
    )
    assert card["old_name"] == "a b c"
    assert len(card["new_name"]) == 20


def test_card_unicode_blob_survives_capping():
    card = trim.candidate_card(
        _candidate(decompile="\u4e2d\u6587\U0001f680\n" * 100), max_lines=5, max_chars=50
    )
    assert card["truncated"] == ["decompile"]
    assert len(card["decompile"]) <= 50
    assert card["decompile"].encode("utf-8").decode("utf-8")


def test_card_rejects_non_mappings_and_bad_caps():
    with pytest.raises(TypeError):
        trim.candidate_card(["not", "a", "mapping"])
    with pytest.raises(ValueError):
        trim.candidate_card(_candidate(), max_lines=0)


def test_candidate_cards_top_k_caps_the_list_and_keeps_the_order():
    candidates = [_candidate(old_ea=0x1000 + i, new_ea=0x2000 + i) for i in range(5)]
    cards = trim.candidate_cards(candidates, limit=3)
    assert [card["old_ea"] for card in cards] == [0x1000, 0x1001, 0x1002]
    assert len(trim.candidate_cards(candidates, limit=None)) == 5
    assert trim.candidate_cards([], limit=3) == []


def test_candidate_cards_passes_caps_through_to_every_card():
    candidates = [_candidate(decompile="q" * 900) for _ in range(3)]
    cards = trim.candidate_cards(candidates, limit=10, max_chars=50, max_lines=None)
    for card in cards:
        assert len(card["decompile"]) <= 50
        assert card["truncated"] == ["decompile"]
