"""icepick diff — Diaphora diff exports into rebase-candidate records (U-IDA5).

Diaphora is the de-facto IDA diffing tool, and its exports are **SQLite
databases**.  icepick neither runs Diaphora nor imports IDA here: this module
reads such an export *defensively* and turns it into the rebase-candidate records
the graph plumbing scores:

``read_diaphora(path)``
    Parse the export into a :class:`DiffReport` (functions, matched pairs, every
    row that was skipped and why).  A missing table or a missing required column
    is a :class:`DiffError` that *names the gap*; a single unreadable row is
    skipped and recorded, never a traceback.

``to_rebase_candidates(report)``
    Project a report onto ``[{old_ea, new_ea, score, signals}]``.  ``signals``
    breaks the score down into the evidence behind it — ``name_equal``,
    ``pseudocode_hash_equal``, the Diaphora ``ratio`` and the address shift — so a
    rebase decision can be explained instead of trusted.

Documented export shape
-----------------------
``functions``
    The exported program's functions.  Required: an old-binary address
    (``address``) and ``name``.  Used when present: ``pseudocode_hash1`` /
    ``pseudocode`` (the content signal), ``size``, ``nodes``, ``edges``,
    ``instructions``, ``prototype``, ``function_flags``.

``results``
    The matched pairs of a diff session.  Required: the old-side address
    (``address``) and the new-side address (``address2``).  Used when present:
    ``ratio``, ``name`` / ``name2``, ``description`` and — when the export carries
    them — ``pseudocode_hash1`` / ``pseudocode_hash2``.

``version`` / ``program``
    Optional; read best effort into ``DiffReport.diaphora_version`` and
    ``DiffReport.program``.

Every required column is looked up through the spellings Diaphora versions have
used (``address``/``ea``/``start_ea``, ``address2``/``ea2``/``new_ea``, ...).  When
none of them is present the :class:`DiffError` names the table, the role and the
spellings that were tried; absent *optional* columns are reported in
``DiffReport.notes`` rather than fatal, because a minimal export is still usable.

Stdlib only (``sqlite3`` / ``json`` / ``hashlib`` / ``argparse`` / ``pathlib``):
no IDA, no Diaphora, no third-party dependency.  That is what lets the whole
converter run against synthetic exports built with ``sqlite3`` alone.

The export is opened **read-only** (a ``mode=ro`` URI plus ``PRAGMA query_only``)
so converting a diff can never mutate the artefact under analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import schema

__all__ = [
    "DIFF_VERSION",
    "FUNCTIONS_TABLE",
    "RESULTS_TABLE",
    "SCORE_NAME_WEIGHT",
    "SCORE_PSEUDOCODE_WEIGHT",
    "PSEUDOCODE_TEXT_MAX_CHARS",
    "FUNCTION_ADDRESS_ALIASES",
    "FUNCTION_NAME_ALIASES",
    "RESULT_OLD_ADDRESS_ALIASES",
    "RESULT_NEW_ADDRESS_ALIASES",
    "RESULT_RATIO_ALIASES",
    "SIGNAL_KEYS",
    "DiffError",
    "DiffFunction",
    "DiffResult",
    "DiffReport",
    "read_diaphora",
    "to_rebase_candidates",
    "score_from_signals",
    "report_summary",
    "candidates_document",
    "dumps_document",
    "add_arguments",
    "build_parser",
    "main",
]

PROGRAM = "icepick"
DIFF_VERSION = "v1"

#: Diaphora's table holding the exported program's own functions.
FUNCTIONS_TABLE = "functions"
#: Diaphora's table holding the matched pairs of a diff session.
RESULTS_TABLE = "results"

#: Score weights.  Name and pseudocode equality are the two signals icepick can
#: verify from the export alone; together they reach certainty (1.0).
SCORE_NAME_WEIGHT = 0.4
SCORE_PSEUDOCODE_WEIGHT = 0.6

#: Pseudocode text longer than this is not hashed for the fallback text signal.
PSEUDOCODE_TEXT_MAX_CHARS = 200_000

#: Keys every candidate's ``signals`` mapping carries.
SIGNAL_KEYS: tuple[str, ...] = (
    "name_equal",
    "pseudocode_hash_equal",
    "score",
    "name_compared",
    "pseudocode_basis",
    "ratio",
    "address_shift",
    "description",
)

#: Column spellings accepted for each required/optional role, most canonical first.
FUNCTION_ADDRESS_ALIASES: tuple[str, ...] = (
    "address",
    "ea",
    "start_ea",
    "addr",
    "function_address",
    "address1",
)
FUNCTION_NAME_ALIASES: tuple[str, ...] = ("name", "function_name", "func_name")
FUNCTION_ID_ALIASES: tuple[str, ...] = ("id", "func_id", "function_id")
FUNCTION_HASH_ALIASES: tuple[str, ...] = (
    "pseudocode_hash1",
    "pseudocode_hash",
    "pseudocode_hash_1",
    "hash1",
)
FUNCTION_PSEUDOCODE_ALIASES: tuple[str, ...] = ("pseudocode", "pseudo_code", "decompiled")

RESULT_OLD_ADDRESS_ALIASES: tuple[str, ...] = (
    "address",
    "address1",
    "old_ea",
    "ea",
    "src_address",
    "main_address",
)
RESULT_NEW_ADDRESS_ALIASES: tuple[str, ...] = (
    "address2",
    "new_ea",
    "ea2",
    "dst_address",
    "address_b",
    "address_2",
)
RESULT_RATIO_ALIASES: tuple[str, ...] = ("ratio", "similarity", "score", "similarity_ratio")
RESULT_OLD_NAME_ALIASES: tuple[str, ...] = (
    "name",
    "name1",
    "function_name",
    "function_name1",
    "old_name",
)
RESULT_NEW_NAME_ALIASES: tuple[str, ...] = (
    "name2",
    "function_name2",
    "new_name",
    "name_2",
)
RESULT_DESCRIPTION_ALIASES: tuple[str, ...] = (
    "description",
    "match_description",
    "details",
)
RESULT_OLD_HASH_ALIASES: tuple[str, ...] = (
    "pseudocode_hash1",
    "pseudocode_hash",
    "pseudocode_hash_1",
    "hash1",
)
RESULT_NEW_HASH_ALIASES: tuple[str, ...] = (
    "pseudocode_hash2",
    "pseudocode_hash_2",
    "hash2",
)
RESULT_ID_ALIASES: tuple[str, ...] = ("id", "rowid")

#: Optional integer/string detail columns carried through for provenance.
RESULT_DETAIL_ALIASES: Mapping[str, tuple[str, ...]] = {
    "nodes1": ("nodes1", "nodes"),
    "nodes2": ("nodes2",),
    "edges1": ("edges1", "edges"),
    "edges2": ("edges2",),
    "instructions1": ("instructions1", "instructions"),
    "instructions2": ("instructions2",),
}

#: Table names whose absence is merely noted, never fatal.
OPTIONAL_TABLES: tuple[str, ...] = ("version", "program")


class DiffError(ValueError):
    """A Diaphora export could not be read, or is missing a required piece."""


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DiffFunction:
    """One row of the export's ``functions`` table (the exported program's side)."""

    ea: int
    name: str
    table_id: Any = None
    pseudocode_hash: str | None = None
    #: ``"hash"`` when the export declared a hash, ``"text"`` when it was derived
    #: from the pseudocode text, ``None`` when neither was available.
    pseudocode_hash_source: str | None = None
    size: int | None = None
    nodes: int | None = None
    edges: int | None = None
    instructions: int | None = None
    prototype: str | None = None
    flags: str | None = None


@dataclass(frozen=True)
class DiffResult:
    """One row of the export's ``results`` table (one proposed match)."""

    table_id: Any = None
    old_ea: int | None = None
    new_ea: int | None = None
    old_name: str | None = None
    new_name: str | None = None
    ratio: float | None = None
    description: str | None = None
    old_pseudocode_hash: str | None = None
    new_pseudocode_hash: str | None = None
    #: ``"hash"`` / ``"text"`` / ``"mixed"`` / ``None`` — what the two hashes rest on.
    hash_basis: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DiffReport:
    """A parsed Diaphora export: what it held, and what had to be skipped."""

    path: str
    tables: tuple[str, ...] = ()
    functions: tuple[DiffFunction, ...] = ()
    results: tuple[DiffResult, ...] = ()
    skipped: tuple[Mapping[str, Any], ...] = ()
    notes: tuple[str, ...] = ()
    diaphora_version: str | None = None
    program: Mapping[str, Any] = field(default_factory=dict)

    @property
    def function_eas(self) -> tuple[int, ...]:
        """Sorted effective addresses of the exported program's functions."""
        return tuple(sorted(function.ea for function in self.functions))

    def function_at(self, ea: Any) -> DiffFunction | None:
        """The exported program's function at ``ea``, or ``None`` (never raises)."""
        address = schema.parse_ea(ea)
        if address is None:
            return None
        for function in self.functions:
            if function.ea == address:
                return function
        return None


# ---------------------------------------------------------------------------
# small conversions — every one of them defensive
# ---------------------------------------------------------------------------
def _quote(identifier: Any) -> str:
    """Quote a SQLite identifier (a table/column name coming from ``sqlite_master``)."""
    return '"' + str(identifier).replace('"', '""') + '"'


def _brief(value: Any, limit: int = 80) -> str:
    """A short, printable rendering of ``value`` for skip/notes text."""
    try:
        text = repr(value)
    except Exception:  # pragma: no cover - hostile __repr__
        return f"<{type(value).__name__}>"
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _text(value: Any) -> str | None:
    """Trimmed non-empty ``str``, or ``None`` (bytes are decoded best effort)."""
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", "replace")
        except Exception:  # pragma: no cover - defensive
            return None
    if not isinstance(value, str):
        value = str(value)
    text = value.strip()
    return text or None


def _count(value: Any) -> int | None:
    """Non-negative integer, or ``None`` (bools and junk are rejected, never raised)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _ratio(value: Any) -> float | None:
    """A 0..1 similarity: ``0.87``, ``\"0.87\"`` and ``87`` (percent) all parse."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):  # NaN / inf
        return None
    if 1.0 < number <= 100.0:  # a percentage form
        number = number / 100.0
    if number < 0.0 or number > 1.0:
        return None
    return round(number, 6)


def _ea(value: Any) -> int | None:
    """An effective address from an int or a ``0x...`` string (see ``schema.parse_ea``)."""
    return schema.parse_ea(value)


def _text_digest(text: str) -> str:
    """sha256 over whitespace-normalised text (the fallback content signal)."""
    normalised = " ".join(text.split())
    return hashlib.sha256(normalised.encode("utf-8", "replace")).hexdigest()


def _json_value(value: Any) -> Any:
    """Best-effort JSON-safe rendering of a SQLite value."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


# ---------------------------------------------------------------------------
# sqlite plumbing — read-only, alias tolerant
# ---------------------------------------------------------------------------
def _connect_readonly(path: Path) -> sqlite3.Connection:
    """Open ``path`` so that conversion cannot write to the export."""
    conn: sqlite3.Connection | None = None
    try:
        uri = f"{path.resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    except (sqlite3.Error, ValueError):  # pragma: no cover - exotic path spellings
        conn = None
    if conn is None:
        conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = ON")
    except sqlite3.Error:  # pragma: no cover - older SQLite
        pass
    return conn


def _sqlite_tables(conn: sqlite3.Connection) -> dict[str, str]:
    """``{lowercased name: real name}`` for every table and view in the export."""
    return {
        str(row[0]).lower(): str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        )
    }


def _column_map(conn: sqlite3.Connection, table: str) -> dict[str, str]:
    """``{lowercased column: real column}`` for ``table``."""
    rows = conn.execute(f"PRAGMA table_info({_quote(table)})").fetchall()
    return {str(row[1]).lower(): str(row[1]) for row in rows}


def _pick_column(
    columns: Mapping[str, str],
    aliases: Sequence[str],
    *,
    table: str,
    role: str,
) -> str:
    """Resolve a required column, or raise :class:`DiffError` naming the gap."""
    for alias in aliases:
        found = columns.get(alias.lower())
        if found:
            return found
    tried = ", ".join(repr(alias) for alias in aliases)
    present = ", ".join(sorted(columns.values())) or "(no columns)"
    raise DiffError(
        f"{table}: missing {role} column: expected one of {tried}; "
        f"the table has: {present}"
    )


def _optional_column(columns: Mapping[str, str], aliases: Sequence[str]) -> str | None:
    """Resolve an optional column, or ``None`` when the export does not carry it."""
    for alias in aliases:
        found = columns.get(alias.lower())
        if found:
            return found
    return None


def _rows(
    conn: sqlite3.Connection, table: str, columns: Sequence[str]
) -> Iterable[sqlite3.Row]:
    """Rows of ``table`` restricted to ``columns``, in stable rowid order."""
    selection = ", ".join(_quote(column) for column in columns)
    quoted = _quote(table)
    try:
        return conn.execute(f"SELECT {selection} FROM {quoted} ORDER BY rowid")
    except sqlite3.Error:  # pragma: no cover - WITHOUT ROWID exports
        return conn.execute(f"SELECT {selection} FROM {quoted}")


# ---------------------------------------------------------------------------
# reading the export
# ---------------------------------------------------------------------------
def read_diaphora(path: Any) -> DiffReport:
    """Parse a Diaphora SQLite diff export into a :class:`DiffReport`.

    Raises :class:`DiffError` — never a raw traceback — when the file is missing,
    is not SQLite, is not a Diaphora export (a required table is absent) or lacks a
    required column.  Individual rows that cannot be interpreted are skipped and
    recorded in ``DiffReport.skipped``.  The export is opened read-only.
    """
    db_path = Path(str(path))
    if not db_path.exists():
        raise DiffError(f"no such Diaphora export: {db_path}")
    if db_path.is_dir():
        raise DiffError(f"{db_path}: is a directory, expected a Diaphora SQLite export")

    try:
        conn = _connect_readonly(db_path)
    except sqlite3.Error as exc:
        raise DiffError(f"{db_path}: cannot open as a SQLite database: {exc}") from exc

    try:
        return _read_report(conn, db_path)
    except DiffError:
        raise
    except sqlite3.Error as exc:
        raise DiffError(f"{db_path}: not a readable Diaphora export: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - the contract is "never a traceback"
        raise DiffError(
            f"{db_path}: cannot parse the Diaphora export: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    finally:
        conn.close()


def _read_report(conn: sqlite3.Connection, db_path: Path) -> DiffReport:
    tables = _sqlite_tables(conn)
    missing = [name for name in (FUNCTIONS_TABLE, RESULTS_TABLE) if name not in tables]
    if missing:
        found = ", ".join(sorted(tables)) or "(no tables)"
        raise DiffError(
            f"{db_path}: not a Diaphora export: missing table(s) "
            + ", ".join(repr(name) for name in missing)
            + f"; a Diaphora diff export has {FUNCTIONS_TABLE!r} and {RESULTS_TABLE!r}; "
            f"found: {found}"
        )

    notes: list[str] = []
    functions, skipped = _read_functions(conn, tables[FUNCTIONS_TABLE], notes)
    by_ea = {function.ea: function for function in functions}
    results, result_skips = _read_results(conn, tables[RESULTS_TABLE], by_ea, notes)
    skipped.extend(result_skips)

    for name in OPTIONAL_TABLES:
        if name not in tables:
            notes.append(f"{name}: optional table absent (provenance detail only)")

    return DiffReport(
        path=str(db_path),
        tables=tuple(sorted(tables.values())),
        functions=functions,
        results=results,
        skipped=tuple(skipped),
        notes=tuple(notes),
        diaphora_version=_diaphora_version(conn, tables),
        program=_program_row(conn, tables),
    )


def _read_functions(
    conn: sqlite3.Connection, table: str, notes: list[str]
) -> tuple[tuple[DiffFunction, ...], list[dict[str, Any]]]:
    """Read the ``functions`` table: the exported program's own functions."""
    columns = _column_map(conn, table)
    address_column = _pick_column(
        columns, FUNCTION_ADDRESS_ALIASES, table=table, role="function address"
    )
    name_column = _pick_column(
        columns, FUNCTION_NAME_ALIASES, table=table, role="function name"
    )
    id_column = _optional_column(columns, FUNCTION_ID_ALIASES)
    hash_column = _optional_column(columns, FUNCTION_HASH_ALIASES)
    pseudocode_column = _optional_column(columns, FUNCTION_PSEUDOCODE_ALIASES)
    detail_columns = {
        "size": _optional_column(columns, ("size", "func_size")),
        "nodes": _optional_column(columns, ("nodes",)),
        "edges": _optional_column(columns, ("edges",)),
        "instructions": _optional_column(columns, ("instructions", "instruction_count")),
        "prototype": _optional_column(columns, ("prototype", "prototype2", "type")),
        "flags": _optional_column(columns, ("function_flags", "flags")),
    }

    if hash_column is None and pseudocode_column is None:
        notes.append(
            f"{table}: no pseudocode_hash*/pseudocode column: pseudocode_hash_equal "
            "stays false for every pair"
        )

    selected = [address_column, name_column]
    if id_column:
        selected.append(id_column)
    for column in (hash_column, pseudocode_column, *detail_columns.values()):
        if column and column not in selected:
            selected.append(column)

    functions: list[DiffFunction] = []
    skipped: list[dict[str, Any]] = []
    seen: set[int] = set()
    for ordinal, row in enumerate(_rows(conn, table, selected), start=1):
        data = dict(row)
        ea = _ea(data.get(address_column))
        if ea is None:
            skipped.append(
                {
                    "table": table,
                    "row": ordinal,
                    "reason": "unparsable function address: "
                    + _brief(data.get(address_column)),
                }
            )
            continue
        if ea in seen:
            skipped.append(
                {
                    "table": table,
                    "row": ordinal,
                    "reason": f"duplicate function address {ea:#x}",
                }
            )
            continue
        seen.add(ea)
        hash_value, hash_source = _pseudocode_hash(data, hash_column, pseudocode_column)
        functions.append(
            DiffFunction(
                ea=ea,
                name=_text(data.get(name_column)) or f"sub_{ea:x}",
                table_id=data.get(id_column) if id_column else None,
                pseudocode_hash=hash_value,
                pseudocode_hash_source=hash_source,
                size=_count(data.get(detail_columns["size"]))
                if detail_columns["size"]
                else None,
                nodes=_count(data.get(detail_columns["nodes"]))
                if detail_columns["nodes"]
                else None,
                edges=_count(data.get(detail_columns["edges"]))
                if detail_columns["edges"]
                else None,
                instructions=_count(data.get(detail_columns["instructions"]))
                if detail_columns["instructions"]
                else None,
                prototype=_text(data.get(detail_columns["prototype"]))
                if detail_columns["prototype"]
                else None,
                flags=_text(data.get(detail_columns["flags"]))
                if detail_columns["flags"]
                else None,
            )
        )
    return tuple(functions), skipped


def _pseudocode_hash(
    data: Mapping[str, Any],
    hash_column: str | None,
    pseudocode_column: str | None,
) -> tuple[str | None, str | None]:
    """``(hash, source)`` for one function: a declared hash, else a text digest."""
    declared = _text(data.get(hash_column)) if hash_column else None
    if declared:
        return declared, "hash"
    pseudo = _text(data.get(pseudocode_column)) if pseudocode_column else None
    if pseudo:
        if len(pseudo) > PSEUDOCODE_TEXT_MAX_CHARS:
            pseudo = pseudo[:PSEUDOCODE_TEXT_MAX_CHARS]
        return _text_digest(pseudo), "text"
    return None, None


def _read_results(
    conn: sqlite3.Connection,
    table: str,
    functions_by_ea: Mapping[int, DiffFunction],
    notes: list[str],
) -> tuple[tuple[DiffResult, ...], list[dict[str, Any]]]:
    """Read the ``results`` table: the matched pairs of the diff session."""
    columns = _column_map(conn, table)
    old_column = _pick_column(
        columns, RESULT_OLD_ADDRESS_ALIASES, table=table, role="old-side address"
    )
    new_column = _pick_column(
        columns, RESULT_NEW_ADDRESS_ALIASES, table=table, role="new-side address"
    )
    id_column = _optional_column(columns, RESULT_ID_ALIASES)
    ratio_column = _optional_column(columns, RESULT_RATIO_ALIASES)
    old_name_column = _optional_column(columns, RESULT_OLD_NAME_ALIASES)
    new_name_column = _optional_column(columns, RESULT_NEW_NAME_ALIASES)
    description_column = _optional_column(columns, RESULT_DESCRIPTION_ALIASES)
    old_hash_column = _optional_column(columns, RESULT_OLD_HASH_ALIASES)
    new_hash_column = _optional_column(columns, RESULT_NEW_HASH_ALIASES)

    if ratio_column is None:
        notes.append(
            f"{table}: no ratio/similarity column: candidate scores rest on the "
            "name and pseudocode signals alone"
        )
    if new_name_column is None and new_hash_column is None:
        notes.append(
            f"{table}: no name2/pseudocode_hash2 column: the new-side name and "
            "content signals are unavailable for every pair"
        )

    selected = [old_column, new_column]
    for column in (
        id_column,
        ratio_column,
        old_name_column,
        new_name_column,
        description_column,
        old_hash_column,
        new_hash_column,
    ):
        if column and column not in selected:
            selected.append(column)

    results: list[DiffResult] = []
    skipped: list[dict[str, Any]] = []
    for ordinal, row in enumerate(_rows(conn, table, selected), start=1):
        data = dict(row)
        old_ea = _ea(data.get(old_column))
        new_ea = _ea(data.get(new_column))
        if old_ea is None or new_ea is None:
            which = "old" if old_ea is None else "new"
            value = data.get(old_column) if old_ea is None else data.get(new_column)
            skipped.append(
                {
                    "table": table,
                    "row": ordinal,
                    "reason": f"unparsable {which}-side address: {_brief(value)}",
                }
            )
            continue

        old_function = functions_by_ea.get(old_ea)
        old_name = _text(data.get(old_name_column)) if old_name_column else None
        if old_name is None and old_function is not None:
            old_name = old_function.name
        new_name = _text(data.get(new_name_column)) if new_name_column else None

        old_hash = _text(data.get(old_hash_column)) if old_hash_column else None
        old_source = "hash" if old_hash else None
        if old_hash is None and old_function is not None and old_function.pseudocode_hash:
            old_hash = old_function.pseudocode_hash
            old_source = old_function.pseudocode_hash_source
        new_hash = _text(data.get(new_hash_column)) if new_hash_column else None
        new_source = "hash" if new_hash else None

        if old_source and new_source:
            basis = old_source if old_source == new_source else "mixed"
        else:
            basis = None

        details: dict[str, Any] = {}
        for key, aliases in RESULT_DETAIL_ALIASES.items():
            column = _optional_column(columns, aliases)
            if column:
                details[key] = _json_value(data.get(column))

        results.append(
            DiffResult(
                table_id=data.get(id_column) if id_column else None,
                old_ea=old_ea,
                new_ea=new_ea,
                old_name=old_name,
                new_name=new_name,
                ratio=_ratio(data.get(ratio_column)) if ratio_column else None,
                description=_text(data.get(description_column))
                if description_column
                else None,
                old_pseudocode_hash=old_hash,
                new_pseudocode_hash=new_hash,
                hash_basis=basis,
                details=details,
            )
        )
    return tuple(results), skipped


def _diaphora_version(conn: sqlite3.Connection, tables: Mapping[str, str]) -> str | None:
    """The Diaphora version that wrote the export, when the table is there."""
    table = tables.get("version")
    if table is None:
        return None
    try:
        for row in conn.execute(f"SELECT * FROM {_quote(table)} LIMIT 1"):
            for value in tuple(row):
                text = _text(value)
                if text:
                    return text
    except sqlite3.Error:  # pragma: no cover - odd version table
        return None
    return None


def _program_row(conn: sqlite3.Connection, tables: Mapping[str, str]) -> dict[str, Any]:
    """The export's ``program`` metadata (program name, md5, ...), best effort."""
    table = tables.get("program")
    if table is None:
        return {}
    try:
        for row in conn.execute(f"SELECT * FROM {_quote(table)} LIMIT 1"):
            return {str(key): _json_value(value) for key, value in dict(row).items()}
    except sqlite3.Error:  # pragma: no cover - odd program table
        return {}
    return {}


# ---------------------------------------------------------------------------
# scoring + candidates — pure, no database
# ---------------------------------------------------------------------------
def score_from_signals(
    *,
    name_equal: bool,
    pseudocode_hash_equal: bool,
    ratio: float | None = None,
) -> float:
    """Deterministic 0..1 confidence from the available evidence.

    ``name_equal`` adds :data:`SCORE_NAME_WEIGHT`, ``pseudocode_hash_equal`` adds
    :data:`SCORE_PSEUDOCODE_WEIGHT` (both signals therefore reach exactly ``1.0``),
    and Diaphora's own ``ratio`` raises the result when it is *more* confident than
    the signals alone.  No evidence and no ratio means ``0.0``.
    """
    if not isinstance(name_equal, bool) or not isinstance(pseudocode_hash_equal, bool):
        raise DiffError(
            "score_from_signals(): name_equal and pseudocode_hash_equal must be booleans"
        )
    evidence = 0.0
    if name_equal:
        evidence += SCORE_NAME_WEIGHT
    if pseudocode_hash_equal:
        evidence += SCORE_PSEUDOCODE_WEIGHT
    ratio_value = _ratio(ratio)
    if ratio_value is None:
        return round(min(evidence, 1.0), 6)
    return round(min(1.0, max(evidence, ratio_value)), 6)


def _candidate(result: DiffResult) -> dict[str, Any]:
    """One rebase-candidate record for a matched pair (both addresses are known)."""
    old_ea = int(result.old_ea)  # type: ignore[arg-type]
    new_ea = int(result.new_ea)  # type: ignore[arg-type]
    name_compared = bool(result.old_name) and bool(result.new_name)
    name_equal = name_compared and result.old_name == result.new_name
    pseudocode_hash_equal = bool(result.old_pseudocode_hash) and bool(
        result.new_pseudocode_hash
    ) and result.old_pseudocode_hash == result.new_pseudocode_hash
    score = score_from_signals(
        name_equal=name_equal,
        pseudocode_hash_equal=pseudocode_hash_equal,
        ratio=result.ratio,
    )
    signals: dict[str, Any] = {
        "name_equal": name_equal,
        "pseudocode_hash_equal": pseudocode_hash_equal,
        "score": score,
        "name_compared": name_compared,
        "pseudocode_basis": result.hash_basis,
        "ratio": result.ratio,
        "address_shift": new_ea - old_ea,
        "description": result.description,
    }
    candidate: dict[str, Any] = {
        "old_ea": old_ea,
        "new_ea": new_ea,
        "score": score,
        "old_name": result.old_name,
        "new_name": result.new_name,
        "signals": signals,
    }
    if result.details:
        candidate["details"] = dict(result.details)
    return candidate


def to_rebase_candidates(
    report: DiffReport,
    *,
    min_score: float = 0.0,
    limit: int = 0,
) -> list[dict[str, Any]]:
    """Project ``report`` onto rebase-candidate records.

    Returns ``[{old_ea, new_ea, score, signals}]`` (plus ``old_name`` / ``new_name``
    and the export's per-pair detail columns when it carries them), sorted by
    descending score and then by ``(old_ea, new_ea)`` — so the same export always
    yields the same order.  Pairs whose addresses are unusable never appear (they
    are recorded in ``report.skipped`` by :func:`read_diaphora`); duplicate
    ``(old_ea, new_ea)`` pairs collapse onto their best-scoring row.

    ``min_score`` drops candidates below the given 0..1 confidence and ``limit``
    keeps at most that many (``0`` = all).
    """
    if not isinstance(report, DiffReport):
        raise DiffError(
            "to_rebase_candidates() expects a DiffReport from read_diaphora(), "
            f"got {type(report).__name__}"
        )
    if isinstance(min_score, bool) or not isinstance(min_score, (int, float)):
        raise DiffError(f"min_score must be a number between 0 and 1, got {min_score!r}")
    min_score = float(min_score)
    if not 0.0 <= min_score <= 1.0:
        raise DiffError(f"min_score must be between 0 and 1, got {min_score!r}")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise DiffError(f"limit must be a non-negative integer, got {limit!r}")

    best: dict[tuple[int, int], dict[str, Any]] = {}
    for result in report.results:
        if result.old_ea is None or result.new_ea is None:
            continue  # recorded as skipped when the export was read
        candidate = _candidate(result)
        key = (candidate["old_ea"], candidate["new_ea"])
        previous = best.get(key)
        if previous is None or candidate["score"] > previous["score"]:
            best[key] = candidate

    candidates = sorted(
        best.values(), key=lambda item: (-item["score"], item["old_ea"], item["new_ea"])
    )
    if min_score > 0.0:
        candidates = [item for item in candidates if item["score"] >= min_score]
    if limit:
        candidates = candidates[:limit]
    return candidates


def report_summary(report: DiffReport) -> dict[str, Any]:
    """A JSON-safe digest of what the export contained (CLI metadata)."""
    if not isinstance(report, DiffReport):
        raise DiffError(
            f"report_summary() expects a DiffReport, got {type(report).__name__}"
        )
    return {
        "path": report.path,
        "diff_version": DIFF_VERSION,
        "tables": list(report.tables),
        "diaphora_version": report.diaphora_version,
        "program": {str(key): value for key, value in dict(report.program).items()},
        "functions": len(report.functions),
        "results": len(report.results),
        "skipped": len(report.skipped),
        "notes": list(report.notes),
    }


def candidates_document(
    report: DiffReport, candidates: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """The ``diff-import`` document: the export's shape plus the candidates."""
    candidates_list = [dict(candidate) for candidate in candidates]
    return {
        "diff_version": DIFF_VERSION,
        "source": report_summary(report),
        "counts": {"candidates": len(candidates_list)},
        "candidates": candidates_list,
    }


def dumps_document(document: Mapping[str, Any]) -> str:
    """Deterministic JSON text: sorted keys, ``\\n`` newline, no NaN/infinity."""
    return (
        json.dumps(
            document,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def add_arguments(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Add the ``diff-import`` flags to ``parser`` (shared with the icepick CLI)."""
    parser.add_argument(
        "diaphora",
        metavar="EXPORT",
        help="Diaphora SQLite diff export to read",
    )
    parser.add_argument(
        "-o",
        "--out",
        metavar="OUT",
        default=None,
        help="write the candidate JSON here (default: stdout)",
    )
    parser.add_argument(
        "--min-score",
        dest="min_score",
        type=float,
        default=0.0,
        metavar="X",
        help="drop candidates scoring below X (0..1; default: 0.0)",
    )
    parser.add_argument(
        "--limit",
        dest="limit",
        type=int,
        default=0,
        metavar="N",
        help="keep at most N candidates, best first (default: 0 = all)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="write the document but print nothing on success",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Standalone parser for ``python -m icepick.diff``."""
    parser = argparse.ArgumentParser(
        prog=f"{PROGRAM} diff-import",
        description=(
            "Read a Diaphora SQLite diff export and print rebase candidates "
            "as JSON."
        ),
    )
    return add_arguments(parser)


def _coerce_args(argv: Any = None) -> argparse.Namespace:
    """Accept either a pre-parsed namespace (from the icepick CLI) or argv."""
    if isinstance(argv, argparse.Namespace):
        return argv
    raw = list(argv) if argv is not None else None
    if raw and raw[0] == "diff-import":
        raw = raw[1:]
    return build_parser().parse_args(raw)


def _fail(message: str) -> int:
    print(f"{PROGRAM}: diff-import: {message}", file=sys.stderr)
    return 1


def main(argv: Any = None, *, report: DiffReport | None = None) -> int:
    """``icepick diff-import`` entry point; returns the process exit code.

    ``report`` is a test seam: pass a hand-built :class:`DiffReport` to exercise the
    rendering and file writing with no SQLite export on disk.
    """
    args = _coerce_args(argv)
    source = getattr(args, "diaphora", None)
    if report is None and not source:
        print(
            f"{PROGRAM}: diff-import: a Diaphora EXPORT path is required",
            file=sys.stderr,
        )
        return 2

    min_score = getattr(args, "min_score", 0.0)
    limit = getattr(args, "limit", 0)
    out = getattr(args, "out", None)
    quiet = bool(getattr(args, "quiet", False))

    try:
        if report is None:
            report = read_diaphora(source)
        candidates = to_rebase_candidates(report, min_score=min_score, limit=limit)
    except DiffError as exc:
        return _fail(str(exc))

    text = dumps_document(candidates_document(report, candidates))
    if out in (None, "-"):
        sys.stdout.write(text)
        return 0

    destination = Path(str(out))
    if destination.parent and not destination.parent.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" keeps the bytes identical on every platform.
    destination.write_text(text, encoding="utf-8", newline="\n")
    if not quiet:
        print(
            f"{PROGRAM}: diff-import: wrote {destination} "
            f"({len(candidates)} candidate(s) from {report.path})"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
