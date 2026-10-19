"""icepick trim — bounded output for the live lanes (U-IDA6).

The live lanes (IDAPython snippets pasted into a Code-Mode agent, official MCP
tool results, decompiler dumps) fail in one characteristic way: they emit *too
much*.  A whole-IDB dump, an unbounded ``str(cfunc)``, a vtable blob pasted into
a transcript — each of those burns the caller's context and tells the analyst
nothing.  This module is the pure, IDA-free half of the fence that bounds those
emits (``docs/UNIT-IDA-PLAN.md``, U-IDA6):

``truncate_text(s, max_lines, max_chars)``
    The one primitive: returns ``(text, truncated_bool)``.  Two independent
    axes apply in a fixed order — **lines first, then characters** — and the
    result never exceeds ``max_chars`` characters.  ``None`` disables one axis.

``cap_sequence(values, limit)``
    Top-K capping for lists (callers, callees, xrefs, candidates): returns
    ``(kept, truncated_bool)``.

``candidate_card(candidate)``
    One rebase-candidate record reduced to what a human or a model can act on:
    **an ID, both effective addresses, both names, a score, bounded signals and
    capped decompile/pseudocode text**.  Blobs are never forwarded; what was cut
    is *named* in ``truncated`` instead of silently dropped.

Rules this module encodes (read them before changing a default):

* **IDs, not blobs.**  A card carries ``id``/``old_ea``/``new_ea`` and capped
  text.  Bulk data goes through ``icepick ingest``, not through a transcript.
* **Deterministic.**  Every cap is a pure function of the input: no clock, no
  counter, no ``id()``, no mapping-iteration order (signal keys are sorted, the
  ``truncated`` list has a fixed order).
* **Code-point safe.**  A cut never splits a surrogate pair, never strands a
  combining mark, a ZWJ/ZWNJ or a variation selector, and never leaves a
  dangling joiner.  The result can therefore be *shorter* than ``max_chars``.
* **JSON-safe.**  Cards hold ``str`` / ``int`` / ``float`` / ``bool`` /
  ``None`` / lists of those only, with non-finite floats dropped — so
  ``json.dumps(card, allow_nan=False)`` always succeeds.

Stdlib only (``hashlib`` / ``json`` / ``math`` / ``unicodedata`` / ``schema``),
and — like everything else in ``src/`` except :mod:`icepick.extract` — it never
imports an IDA module, so it is unit-testable with no IDA runtime anywhere.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

from . import schema

__all__ = [
    "DEFAULT_MAX_LINES",
    "DEFAULT_MAX_CHARS",
    "DEFAULT_MAX_ITEMS",
    "DEFAULT_MAX_NAME_CHARS",
    "TRUNCATION_MARK",
    "JOINER_CHARS",
    "DECOMPILE_ALIASES",
    "PSEUDOCODE_ALIASES",
    "OLD_EA_ALIASES",
    "NEW_EA_ALIASES",
    "OLD_NAME_ALIASES",
    "NEW_NAME_ALIASES",
    "ID_ALIASES",
    "CARD_TRUNCATED_ORDER",
    "normalize_newlines",
    "safe_cut",
    "truncate_chars",
    "truncate_lines",
    "truncate_text",
    "cap_sequence",
    "one_line",
    "candidate_id",
    "candidate_card",
    "candidate_cards",
]

#: Line budget of one emitted text blob (decompiler text, pseudocode, listing).
DEFAULT_MAX_LINES = 200
#: Character budget of one emitted text blob; hard, marker included.
DEFAULT_MAX_CHARS = 8000
#: Top-K budget of one emitted list (callers, callees, xrefs, cards).
DEFAULT_MAX_ITEMS = 50
#: Budget of a single-line field (name, signal string, id).
DEFAULT_MAX_NAME_CHARS = 120

#: What a caller may append to visibly mark a cut; costs characters, so it is
#: carved out of the ``max_chars`` budget rather than added on top of it.
TRUNCATION_MARK = "\u2026"

#: Zero-width joiners/non-joiners: meaningless at either end of a cut.
JOINER_CHARS: tuple[str, ...] = ("\u200c", "\u200d")

#: Variation selectors (BMP + supplementary planes), also meaningless alone.
_VARIATION_SELECTOR_RANGES: tuple[tuple[int, int], ...] = (
    (0xFE00, 0xFE0F),
    (0xE0100, 0xE01EF),
)

#: Candidate keys holding the decompiler text, in priority order.
DECOMPILE_ALIASES: tuple[str, ...] = ("decompile", "decompiled", "decompilation")
#: Candidate keys holding pseudocode when it is carried separately.
PSEUDOCODE_ALIASES: tuple[str, ...] = (
    "pseudocode",
    "pseudo_code",
    "pseudo",
    "code",
    "text",
)
#: Candidate keys holding the old-side / new-side effective address.
OLD_EA_ALIASES: tuple[str, ...] = ("old_ea", "ea", "address", "old_address", "ea1")
NEW_EA_ALIASES: tuple[str, ...] = ("new_ea", "ea2", "address2", "new_address")
#: Candidate keys holding the old-side / new-side symbol name.
OLD_NAME_ALIASES: tuple[str, ...] = ("old_name", "name", "name1")
NEW_NAME_ALIASES: tuple[str, ...] = ("new_name", "name2")
#: Candidate keys carrying an already-assigned card/record id.
ID_ALIASES: tuple[str, ...] = ("id", "candidate_id", "card_id", "key")

#: Fixed order of the ``truncated`` list, so cards are comparable byte for byte.
CARD_TRUNCATED_ORDER: tuple[str, ...] = ("decompile", "pseudocode")

#: Wrapper key whose mapping is consulted after the candidate's own keys
#: (Diaphora exports put per-pair detail columns under ``details``).
_DETAIL_KEY = "details"


# ---------------------------------------------------------------------------
# argument checks
# ---------------------------------------------------------------------------
def _check_cap(value: Any, name: str) -> None:
    """``None`` (uncapped) or a positive ``int`` — anything else is a bug."""
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be a positive integer or None, got {value!r}")
    if value < 1:
        raise ValueError(f"{name} must be >= 1 (or None for no cap), got {value!r}")


def _check_marker(marker: Any) -> None:
    if not isinstance(marker, str):
        raise TypeError(f"marker must be a string, got {type(marker).__name__}")


# ---------------------------------------------------------------------------
# text primitives
# ---------------------------------------------------------------------------
def normalize_newlines(text: str) -> str:
    """``\\r\\n`` and lone ``\\r`` become ``\\n`` (line counting must not lie)."""
    if not isinstance(text, str):
        raise TypeError(f"normalize_newlines() expects a string, got {type(text).__name__}")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _dangling_end(ch: str) -> bool:
    """True for a code point that cannot stand alone at the end of a kept prefix."""
    if not ch:
        return False
    if ch in JOINER_CHARS:
        return True
    if unicodedata.combining(ch):
        return True
    code = ord(ch)
    return any(low <= code <= high for low, high in _VARIATION_SELECTOR_RANGES)


def _needs_backoff(text: str, cut: int) -> bool:
    """True when ``text[:cut]`` would split a surrogate pair or a grapheme glue."""
    if cut <= 0 or cut >= len(text):
        return False
    last = text[cut - 1]
    nxt = text[cut]
    if 0xD800 <= ord(last) <= 0xDBFF and 0xDC00 <= ord(nxt) <= 0xDFFF:
        return True  # a lone high surrogate must never be the last kept character
    if _dangling_end(last):
        return True  # kept text must not end on a mark, a joiner or a selector
    # What sits at ``text[cut]`` matters only when dropping it would detach it from
    # its base: a combining mark would be orphaned, so back off one further (base
    # and mark are kept or dropped together).  A ZWJ/ZWNJ or a variation selector
    # is glue that points *backwards*, so the base kept before it stays intact and
    # the cut is safe there.
    return unicodedata.combining(nxt) > 0


def safe_cut(text: str, limit: int) -> str:
    """First ``limit`` characters of ``text``, backed off to a safe boundary.

    The returned prefix is never longer than ``limit`` and may be shorter when
    the boundary would have split a surrogate pair, separated a base character
    from its combining mark, or stranded a ZWJ/ZWNJ or variation selector.
    """
    if not isinstance(text, str):
        raise TypeError(f"safe_cut() expects a string, got {type(text).__name__}")
    _check_cap(limit, "limit")
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    cut = limit
    while cut > 0 and _needs_backoff(text, cut):
        cut -= 1
    return text[:cut]


def truncate_chars(text: str, max_chars: int | None = DEFAULT_MAX_CHARS) -> tuple[str, bool]:
    """``(text, truncated)`` capped to ``max_chars`` characters (never longer)."""
    _check_cap(max_chars, "max_chars")
    if not isinstance(text, str):
        raise TypeError(f"truncate_chars() expects a string, got {type(text).__name__}")
    if max_chars is None or len(text) <= max_chars:
        return text, False
    return safe_cut(text, max_chars), True


def truncate_lines(text: str, max_lines: int | None = DEFAULT_MAX_LINES) -> tuple[str, bool]:
    """``(text, truncated)`` capped to ``max_lines`` lines.

    Line counting follows :meth:`str.splitlines`, so a trailing newline does not
    invent an extra empty line and a document that already fits is returned
    **unchanged** (byte for byte).
    """
    _check_cap(max_lines, "max_lines")
    if not isinstance(text, str):
        raise TypeError(f"truncate_lines() expects a string, got {type(text).__name__}")
    if max_lines is None:
        return text, False
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text, False
    return "\n".join(lines[:max_lines]), True


def truncate_text(
    s: str | None,
    max_lines: int | None = DEFAULT_MAX_LINES,
    max_chars: int | None = DEFAULT_MAX_CHARS,
    *,
    marker: str = "",
) -> tuple[str, bool]:
    """Bound ``s`` on two axes: ``(text, truncated_bool)``.

    Order is fixed and therefore reproducible: newlines are normalised
    (``\\r\\n`` → ``\\n``), then the **line** cap applies, then the **character**
    cap.  ``truncated`` is ``True`` when either axis dropped something; a
    pure newline normalisation is *not* truncation.

    ``None`` disables an axis.  ``marker`` (e.g. :data:`TRUNCATION_MARK`) is
    carved *out of* the character budget and appended only when it fits, so
    ``len(result) <= max_chars`` always holds.  A cut is code-point safe (see
    :func:`safe_cut`), which is the only reason the result may come back shorter
    than the budget.
    """
    _check_cap(max_lines, "max_lines")
    _check_cap(max_chars, "max_chars")
    _check_marker(marker)
    if s is None:
        return "", False
    if not isinstance(s, str):
        raise TypeError(f"truncate_text() expects a string or None, got {type(s).__name__}")

    text = normalize_newlines(s)
    text, line_truncated = truncate_lines(text, max_lines)

    char_truncated = False
    if max_chars is not None and len(text) > max_chars:
        reserve = len(marker) if marker and len(marker) < max_chars else 0
        text = safe_cut(text, max_chars - reserve) + (marker if reserve else "")
        char_truncated = True
    elif (
        line_truncated
        and marker
        and (max_chars is None or len(text) + len(marker) <= max_chars)
    ):
        text += marker

    return text, bool(line_truncated or char_truncated)


def cap_sequence(
    values: Iterable[Any], limit: int | None = DEFAULT_MAX_ITEMS
) -> tuple[list[Any], bool]:
    """Top-K: ``(kept_items, truncated_bool)`` for any iterable (never mutates it)."""
    _check_cap(limit, "limit")
    items = list(values)
    if limit is None or len(items) <= limit:
        return items, False
    return items[:limit], True


def one_line(text: Any, *, max_chars: int | None = DEFAULT_MAX_NAME_CHARS) -> str:
    """Whitespace-collapsed, stripped, character-capped single-line string."""
    _check_cap(max_chars, "max_chars")
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    collapsed = " ".join(text.split())
    bounded, _ = truncate_chars(collapsed, max_chars)
    return bounded


# ---------------------------------------------------------------------------
# candidate cards
# ---------------------------------------------------------------------------
def _detail_mapping(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    detail = candidate.get(_DETAIL_KEY)
    return detail if isinstance(detail, Mapping) else {}


def _first_present(candidate: Mapping[str, Any], aliases: Iterable[str]) -> Any:
    """First alias present on the candidate, then on its ``details`` mapping."""
    sources = (candidate, _detail_mapping(candidate))
    for alias in aliases:
        for source in sources:
            if alias in source:
                return source[alias]
    return None


def _canonical_json(candidate: Mapping[str, Any]) -> str:
    """Stable text digest source: sorted keys, no host detail, never raising."""
    try:
        return json.dumps(
            {str(key): _jsonable(value) for key, value in candidate.items()},
            sort_keys=True,
            ensure_ascii=False,
            default=repr,
        )
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return repr(sorted(str(key) for key in candidate))


def _jsonable(value: Any, *, depth: int = 0) -> Any:
    """Best-effort JSON view of ``value`` (used only to build the id digest)."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping) and depth < 3:
        return {str(key): _jsonable(item, depth=depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)) and depth < 3:
        return [_jsonable(item, depth=depth + 1) for item in value]
    return one_line(value, max_chars=DEFAULT_MAX_NAME_CHARS)


def candidate_id(candidate: Mapping[str, Any]) -> str:
    """Deterministic, short card id for ``candidate``.

    Priority: an explicit id already on the record (``id`` / ``candidate_id`` /
    ``card_id`` / ``key``) → ``ea-<old:x>-<new:x>`` when both addresses are
    usable → ``c<sha1 of the record's canonical JSON>[..12]``.  Same record in,
    same id out, whatever order its keys arrived in.
    """
    if not isinstance(candidate, Mapping):
        raise TypeError(
            f"candidate_id() expects a mapping, got {type(candidate).__name__}"
        )
    explicit = _first_present(candidate, ID_ALIASES)
    if explicit is not None:
        text = one_line(explicit, max_chars=DEFAULT_MAX_NAME_CHARS)
        if text:
            return text
    old_ea = schema.parse_ea(_first_present(candidate, OLD_EA_ALIASES))
    new_ea = schema.parse_ea(_first_present(candidate, NEW_EA_ALIASES))
    if old_ea is not None and new_ea is not None:
        return f"ea-{old_ea:x}-{new_ea:x}"
    digest = hashlib.sha1(  # noqa: S324 - identity digest, not a security control
        _canonical_json(candidate).encode("utf-8", errors="replace")
    ).hexdigest()
    return f"c{digest[:12]}"


def _finite_number(value: Any) -> float | None:
    """``float`` for a usable finite number, else ``None`` (bools are not numbers)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return round(number, 6)


def _bounded_signals(
    signals: Mapping[str, Any], *, max_name_chars: int
) -> tuple[dict[str, Any], list[str]]:
    """Primitive-only view of ``signals`` plus the keys that had to be dropped.

    Keys are visited in sorted order so the result does not depend on how the
    producer built the mapping.  Nested containers and non-finite floats are
    dropped **by name** (``omitted_signals``) — a count of the evidence kept,
    never the evidence itself.
    """
    kept: dict[str, Any] = {}
    omitted: list[str] = []
    for raw_key in sorted(signals, key=str):
        key = one_line(raw_key, max_chars=max_name_chars) or str(raw_key)
        value = signals[raw_key]
        if value is None or isinstance(value, bool):
            kept[key] = value
        elif isinstance(value, int):
            kept[key] = value
        elif isinstance(value, float):
            number = _finite_number(value)
            if number is None:
                omitted.append(key)
            else:
                kept[key] = number
        elif isinstance(value, str):
            kept[key] = one_line(value, max_chars=max_name_chars)
        else:
            omitted.append(key)
    return kept, omitted


def _capped_text(
    raw: Any,
    *,
    max_lines: int | None,
    max_chars: int | None,
    marker: str,
) -> tuple[str, bool, dict[str, int]]:
    """Bound one blob: ``(text, truncated, counts)``; non-strings are ``absent``."""
    if not isinstance(raw, str):
        return "", False, {"lines": 0, "chars": 0}
    text, truncated = truncate_text(raw, max_lines, max_chars, marker=marker)
    return text, truncated, {"lines": len(raw.splitlines()), "chars": len(raw)}


def candidate_card(
    candidate: Mapping[str, Any],
    *,
    max_lines: int | None = DEFAULT_MAX_LINES,
    max_chars: int | None = DEFAULT_MAX_CHARS,
    max_name_chars: int | None = DEFAULT_MAX_NAME_CHARS,
    marker: str = TRUNCATION_MARK,
) -> dict[str, Any]:
    """Reduce one candidate record to a bounded, JSON-safe card.

    The card keeps **identity** (``id``, ``old_ea``, ``new_ea``, both names),
    **decidability** (``score``, ``ratio``, ``address_shift``, bounded
    ``signals``) and **capped text** (``decompile`` / ``pseudocode``).  Nothing
    else crosses the boundary: a decompiler dump is cut to ``max_lines`` /
    ``max_chars``, signal strings are collapsed to one line, containers inside
    ``signals`` are dropped and named in ``omitted_signals``.

    ``truncated`` lists the fields that were cut, in :data:`CARD_TRUNCATED_ORDER`
    (never dict order), and ``counts`` reports the pre-cap size of each blob, so
    a reader can tell "short because the function is short" from "short because
    we cut it".
    """
    if not isinstance(candidate, Mapping):
        raise TypeError(
            f"candidate_card() expects a mapping, got {type(candidate).__name__}"
        )
    _check_cap(max_lines, "max_lines")
    _check_cap(max_chars, "max_chars")
    _check_cap(max_name_chars, "max_name_chars")
    _check_marker(marker)

    raw_signals = candidate.get("signals")
    signals, omitted = _bounded_signals(
        raw_signals if isinstance(raw_signals, Mapping) else {},
        max_name_chars=max_name_chars or DEFAULT_MAX_NAME_CHARS,
    )

    old_ea = schema.parse_ea(_first_present(candidate, OLD_EA_ALIASES))
    new_ea = schema.parse_ea(_first_present(candidate, NEW_EA_ALIASES))

    score = _finite_number(_first_present(candidate, ("score",)))
    if score is None:
        score = _finite_number(signals.get("score"))
    ratio = _finite_number(_first_present(candidate, ("ratio", "similarity")))
    if ratio is None:
        ratio = _finite_number(signals.get("ratio"))

    shift = _finite_number(_first_present(candidate, ("address_shift",)))
    if shift is None:
        shift = _finite_number(signals.get("address_shift"))
    if shift is None and old_ea is not None and new_ea is not None:
        shift = float(new_ea - old_ea)

    truncated: list[str] = []
    counts: dict[str, dict[str, int]] = {}
    texts: dict[str, str] = {}
    groups = (
        ("decompile", DECOMPILE_ALIASES),
        ("pseudocode", PSEUDOCODE_ALIASES),
    )
    for field, aliases in groups:
        text, was_truncated, field_counts = _capped_text(
            _first_present(candidate, aliases),
            max_lines=max_lines,
            max_chars=max_chars,
            marker=marker,
        )
        texts[field] = text
        counts[field] = field_counts
        if was_truncated:
            truncated.append(field)

    return {
        "id": candidate_id(candidate),
        "score": score,
        "ratio": ratio,
        "old_ea": old_ea,
        "new_ea": new_ea,
        "address_shift": None if shift is None else int(shift),
        "old_name": one_line(
            _first_present(candidate, OLD_NAME_ALIASES), max_chars=max_name_chars
        ),
        "new_name": one_line(
            _first_present(candidate, NEW_NAME_ALIASES), max_chars=max_name_chars
        ),
        "decompile": texts["decompile"],
        "pseudocode": texts["pseudocode"],
        "counts": {field: dict(counts[field]) for field, _ in groups},
        "truncated": sorted(truncated, key=CARD_TRUNCATED_ORDER.index),
        "omitted_signals": sorted(set(omitted)),
        "signals": signals,
    }


def candidate_cards(
    candidates: Iterable[Mapping[str, Any]],
    *,
    limit: int | None = DEFAULT_MAX_ITEMS,
    **card_kwargs: Any,
) -> list[dict[str, Any]]:
    """Cards for at most ``limit`` candidates (top-K; ``None`` = all).

    Order is the caller's order — this function never re-ranks, because scoring
    belongs to :func:`icepick.diff.to_rebase_candidates`, not to the fence.  When
    fewer cards come back than candidates went in, the tail was capped.
    """
    kept, _ = cap_sequence(candidates, limit)
    return [candidate_card(candidate, **card_kwargs) for candidate in kept]
