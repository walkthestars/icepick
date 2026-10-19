"""icepick extract — IDA-side inventory emitter (U-IDA2, schema v1).

``extract`` is the **only** module in this package that talks to IDA, and it is
written to run *inside* an IDA process:

* **idalib (standalone, primary)** — :func:`import_ida` pins ``IDADIR`` and then
  imports ``idapro``; :func:`analysis_context` calls
  ``idapro.open_database(path, True)`` (auto-analysis runs and is waited on)
  and closes the database afterwards **without saving**.
* **hosted (IDAPython inside IDA)** — ``idaapi`` is already live and ``idapro``
  refuses to load, so the hosted context is tried **first** (see
  :func:`open_idb`); the world then reports the database IDA already has open
  and auto-analysis is awaited with ``idaapi.auto_wait()`` when still running.

Environment rule (stale-override incident, 2026-10-15 — ``docs/UNIT-IDA-PLAN.md``):
``os.environ['IDADIR']`` is set to the *pinned* install **before** ``import
idapro`` ever runs, because a harness shell can carry a stale ``IDADIR``
(``9.3`` while the pin is ``9.5``).  The inherited value is therefore ignored
unless ``trust_env=True`` is asked for explicitly; the pin comes from
``ida-config.json`` (``Paths.ida-install-dir``), see :func:`pinned_ida_home`.

Determinism (U-IDA2 accept criterion: byte-identical JSON across two runs):
:func:`emit` sorts every list, caps each one at ``top_k`` (default 500) and
records what it capped; :func:`dumps_document` writes ``sort_keys=True`` JSON
with ``\\n`` newlines and the document carries no timestamp, host name, run
counter or absolute output path.  Extraction is read-only: no names are applied
to the database and the IDB is closed with ``save=False``.

Import discipline: importing this module does **not** import IDA — the IDA
import lives in :func:`import_ida` and happens only when extraction actually
runs.  That keeps :func:`resolve_ida_home` and the whole pure half of this
module unit-testable with no IDA runtime anywhere in sight.  Stdlib only
outside the IDA section marked below.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import importlib
import json
import os
import sys
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from . import __version__, schema

__all__ = [
    "PROGRAM",
    "EXTRACT_VERSION",
    "DEFAULT_TOP_K",
    "DECOMPILE_NOT_ATTEMPTED",
    "DECOMPILE_STATUSES",
    "DECOMPILE_TEXT_MAX_CHARS",
    "decompile_func",
    "init_hexrays",
    "XREF_KINDS",
    "IDA_INSTALL_MARKERS",
    "GENERATOR",
    "IDAHomeError",
    "IDAUnavailable",
    "IDANotHosted",
    "ExtractError",
    "is_ida_install",
    "ida_config_paths",
    "ida_install_dir_from_config",
    "find_ida_home",
    "resolve_ida_home",
    "pinned_ida_home",
    "is_hosted",
    "import_ida",
    "open_idb",
    "close_idb",
    "wait_for_auto_analysis",
    "analysis_context",
    "World",
    "RealIdaWorld",
    "FUNC_FLAG_BITS",
    "func_lib_mask",
    "flag_names",
    "sha256_file",
    "idb_sha256",
    "emit",
    "dumps_document",
    "add_arguments",
    "build_parser",
    "main",
]

PROGRAM = "icepick"
EXTRACT_VERSION = schema.SCHEMA_VERSION
DEFAULT_TOP_K = 500

#: Schema sentinel for a decompile that never ran; matches
#: ``schema.DECOMPILE_FAILED_RE``.  U-IDA3 (``decompile_func``) replaces it with
#: real text whenever the decompiler can produce some.
DECOMPILE_NOT_ATTEMPTED = "DECOMPILE_FAILED(not_attempted)"

#: Per-function decompile outcomes accepted by the schema (U-IDA3).
DECOMPILE_STATUSES: tuple[str, ...] = schema.DECOMPILE_STATUSES
#: Hard cap on stored decompiler text; longer output degrades to ``too_big``.
DECOMPILE_TEXT_MAX_CHARS = 200_000
#: Functions larger than this are never handed to the decompiler (``too_big``).
DECOMPILE_TOO_BIG_BYTES = 1 << 18
#: hexrays messages that mean "gave up on size", not on time (classification).
_DECOMPILE_TOO_BIG_MARKERS: tuple[str, ...] = (
    "too big",
    "too_big",
    "too large",
    "capacity",
    "not enough memory",
    "out of memory",
    "allocation failed",
)
#: hexrays messages that mean "gave up on time".
_DECOMPILE_TIMEOUT_MARKERS: tuple[str, ...] = (
    "timed out",
    "timeout",
    "time out",
    "interrupt",
    "cancelled",
    "canceled",
)

GENERATOR = f"icepick.extract {__version__}"

UNKNOWN_IDA_VERSION = "unknown"

#: Xref kinds carried in each function record (``xrefs_to`` / ``xrefs_from``).
XREF_KINDS: tuple[str, ...] = ("call", "jump", "data", "unknown")

#: Files/directories whose presence marks a directory as an IDA install.
IDA_INSTALL_MARKERS: tuple[str, ...] = (
    "idalib.dll",
    "libidalib.so",
    "libidalib.dylib",
    "ida.dll",
    "ida64.dll",
    "libida.so",
    "ida.hlp",
    "ida.int",
    "idc",
    "idalib",
)

#: Keys ``ida-config.json`` is known to use for the install directory.
IDA_CONFIG_KEYS: tuple[str, ...] = (
    "ida-install-dir",
    "ida_install_dir",
    "idadir",
    "install-dir",
    "install_dir",
)

#: ``func_t::flags`` bits worth carrying into the document (IDA SDK values).
FUNC_FLAG_BITS: tuple[tuple[str, int], ...] = (
    ("noret", 0x00000001),
    ("far", 0x00000002),
    ("library", 0x00000004),
    ("static", 0x00000008),
    ("frame", 0x00000010),
    ("userfar", 0x00000020),
    ("hidden", 0x00000040),
    ("thunk", 0x00000080),
    ("bottom_bp", 0x00000100),
    ("tail", 0x00004000),
    ("lumina", 0x00008000),
    ("outline", 0x00010000),
)

#: IDA xref type names (``idaapi.fl_*``) classified as calls / plain jumps.
_CALL_XREF_NAMES = ("fl_CN", "fl_CF")
_JUMP_XREF_NAMES = ("fl_JN", "fl_JF", "fl_F")


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------
class IDAHomeError(ValueError):
    """No usable IDA install directory could be resolved."""


class IDAUnavailable(RuntimeError):
    """The IDA API cannot be imported in this process."""


class IDANotHosted(RuntimeError):
    """No hosted IDA context (``idaapi``) is available — use the idalib lane."""


class ExtractError(ValueError):
    """Extraction failed, or the produced document would not validate."""


# ---------------------------------------------------------------------------
# IDA home resolution — pure: filesystem + JSON only, no IDA import
# ---------------------------------------------------------------------------
def is_ida_install(path: Any) -> bool:
    """True when ``path`` is an existing directory that looks like an IDA install.

    The check is marker-based (:data:`IDA_INSTALL_MARKERS`), so a *stale*
    ``IDADIR`` pointing at a deleted or renamed install is rejected instead of
    being handed to ``idapro``.
    """
    if not path:
        return False
    root = Path(str(path))
    try:
        if not root.is_dir():
            return False
    except OSError:  # pragma: no cover - unreadable path
        return False
    for marker in IDA_INSTALL_MARKERS:
        try:
            if (root / marker).exists():
                return True
        except OSError:  # pragma: no cover - unreadable entry
            continue
    return False


def ida_config_paths(env: Mapping[str, str] | None = None) -> list[Path]:
    """Candidate ``ida-config.json`` locations, most specific first.

    Honours an explicit ``IDA_CONFIG_PATH`` (or the older ``IDACONFIG``)
    override, then the platform locations (``%APPDATA%\\Hex-Rays\\IDA Pro``,
    ``$XDG_CONFIG_HOME``/``~/.config/Hex-Rays/IDA Pro``, ``~/.idapro``).
    """
    env = os.environ if env is None else env
    candidates: list[Path] = []

    override = env.get("IDA_CONFIG_PATH") or env.get("IDACONFIG")
    if override:
        candidates.append(Path(override))

    xdg = env.get("XDG_CONFIG_HOME")
    if xdg:
        candidates.append(Path(xdg) / "Hex-Rays" / "IDA Pro" / "ida-config.json")

    appdata = env.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "Hex-Rays" / "IDA Pro" / "ida-config.json")

    home = env.get("HOME") or env.get("USERPROFILE")
    if home:
        candidates.append(Path(home) / ".idapro" / "ida-config.json")
        candidates.append(Path(home) / ".config" / "Hex-Rays" / "IDA Pro" / "ida-config.json")

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(os.path.normpath(str(candidate)))
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def _search_config_keys(obj: Any) -> str | None:
    """Depth-first search for the first install-directory value in a config tree."""
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            if str(key).strip().lower() in IDA_CONFIG_KEYS and isinstance(value, str):
                if value.strip():
                    return value.strip()
        for value in obj.values():
            found = _search_config_keys(value)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _search_config_keys(value)
            if found:
                return found
    return None


def ida_install_dir_from_config(config_path: Any) -> str | None:
    """Read ``Paths.ida-install-dir`` out of ``config_path``; ``None`` if absent.

    A missing, unreadable or malformed config is not an error here — the caller
    decides whether the absence is fatal.
    """
    try:
        text = Path(config_path).read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return _search_config_keys(payload)


def _normalize_home(value: str) -> str:
    expanded = os.path.expandvars(str(value).strip())
    expanded = os.path.expanduser(expanded)
    return os.path.normpath(expanded)


def find_ida_home(
    *,
    env: Mapping[str, str] | None = None,
    config_path: Any = None,
    trust_env: bool = False,
) -> str | None:
    """Best IDA install directory, or ``None`` (never raises).

    ``trust_env=True`` prefers a *valid* inherited ``IDADIR``; the default
    (``False``) skips it because harness shells carry a stale value
    (environment rule, see the module docstring) and falls back to it only when
    the config yields nothing usable.
    """
    env = os.environ if env is None else env

    inherited = env.get("IDADIR")
    inherited_home = _normalize_home(inherited) if inherited else None
    inherited_ok = bool(inherited_home) and is_ida_install(inherited_home)

    if trust_env and inherited_ok:
        return inherited_home

    configs = (
        [Path(str(config_path))]
        if config_path is not None
        else ida_config_paths(env)
    )
    for candidate in configs:
        configured = ida_install_dir_from_config(candidate)
        if not configured:
            continue
        home = _normalize_home(configured)
        if is_ida_install(home):
            return home

    if inherited_ok:
        return inherited_home
    return None


def resolve_ida_home(
    *,
    env: Mapping[str, str] | None = None,
    config_path: Any = None,
) -> str:
    """Resolve the IDA install directory, preferring a **valid** ``IDADIR``.

    Order: an inherited ``IDADIR`` that exists and looks like an IDA install →
    ``Paths.ida-install-dir`` from ``ida-config.json`` (when that directory is a
    real install) → :class:`IDAHomeError` naming everything that was tried.
    """
    env = os.environ if env is None else env
    inherited = env.get("IDADIR")
    if inherited and is_ida_install(inherited):
        return _normalize_home(inherited)

    found = find_ida_home(env=env, config_path=config_path, trust_env=False)
    if found:
        return found

    tried = ", ".join(str(path) for path in (
        [Path(str(config_path))] if config_path is not None else ida_config_paths(env)
    )) or "no ida-config.json locations found"
    raise IDAHomeError(
        "cannot resolve the IDA install directory: IDADIR "
        f"{inherited!r} is not a valid IDA install and ida-config.json "
        f"(Paths.ida-install-dir) gave nothing usable. Looked at: {tried}"
    )


def pinned_ida_home(
    *,
    env: Mapping[str, str] | None = None,
    config_path: Any = None,
    trust_env: bool = False,
) -> str:
    """The install directory to pin as ``IDADIR`` *before* importing ``idapro``.

    Environment rule: the inherited ``IDADIR`` is ignored by default because a
    harness shell may carry a stale pin; ``ida-config.json`` wins.  A valid
    inherited value is still used when no config is available, so a correctly
    configured machine keeps working.
    """
    found = find_ida_home(env=env, config_path=config_path, trust_env=trust_env)
    if found:
        return found
    env = os.environ if env is None else env
    raise IDAHomeError(
        "cannot pin IDADIR: no usable IDA install directory "
        f"(inherited IDADIR={env.get('IDADIR')!r}; ida-config.json locations: "
        + ", ".join(str(p) for p in (
            [Path(str(config_path))] if config_path is not None else ida_config_paths(env)
        ))
        + ")"
    )


# ---------------------------------------------------------------------------
# IDA section — the only place IDA is touched.
#
# ``idapro`` comes FIRST: it loads idalib and, as a side effect, puts IDA's own
# python directory on sys.path so that ``idaapi``/``idc``/``idautils`` become
# importable.  IDADIR is pinned to the real install *before* that import.
# ---------------------------------------------------------------------------
_IDA_MODULES: dict[str, Any] = {}
_IDA_IMPORT_ERROR: BaseException | None = None

#: Decompiler state: ``None`` = never tried, ``False`` = tried and unavailable.
_HEXRAYS_MODULE: Any | None = None
_HEXRAYS_READY: bool | None = None

#: Pinned ``func_t::flags`` fallback (IDA SDK: ``#define FUNC_LIB 0x00000004``).
FUNC_LIB_FALLBACK = 0x00000004


def is_hosted() -> bool:
    """True when IDA's own Python is hosting us (live database, ``idaapi`` up).

    Mirrors the signal ``idapro`` itself uses (``__main__.IDAPYTHON_VERSION``)
    plus the "idaapi but no idapro" case, which only occurs inside IDA.
    """
    main = sys.modules.get("__main__")
    if getattr(main, "IDAPYTHON_VERSION", None) is not None:
        return True
    return "idaapi" in sys.modules and "idapro" not in sys.modules


def _hosted_modules() -> dict[str, Any]:
    """Modules of a hosted IDA session, or raise :class:`IDANotHosted`."""
    if not is_hosted():
        raise IDANotHosted("no hosted IDA context (standalone run)")
    modules: dict[str, Any] = {}
    for name in ("idaapi", "idc", "idautils"):
        module = sys.modules.get(name)
        if module is None:
            try:
                module = importlib.import_module(name)
            except ImportError as exc:  # pragma: no cover - broken hosted session
                raise IDANotHosted(f"hosted IDA context is missing {name}: {exc}") from exc
        modules[name] = module
    return modules


def import_ida(
    *,
    ida_home: str | None = None,
    trust_env: bool = False,
    config_path: Any = None,
) -> dict[str, Any]:
    """Import the IDA API with ``IDADIR`` pinned **before** the import.

    Standalone: ``os.environ['IDADIR'] = <pinned install>`` → ``import idapro``
    → ``idaapi``.  Hosted: ``idaapi`` is already live and ``idapro`` must not be
    imported at all (it refuses, and would fight the host).  The resolved
    modules are cached for the process; a failed import is remembered so callers
    get a stable, descriptive :class:`IDAUnavailable`.
    """
    global _IDA_MODULES, _IDA_IMPORT_ERROR
    if _IDA_MODULES:
        return dict(_IDA_MODULES)
    if _IDA_IMPORT_ERROR is not None:
        raise IDAUnavailable(
            f"IDA is not importable in this process: {_IDA_IMPORT_ERROR}"
        ) from _IDA_IMPORT_ERROR

    if is_hosted():
        _IDA_MODULES = _hosted_modules()
        return dict(_IDA_MODULES)

    home = ida_home or pinned_ida_home(trust_env=trust_env, config_path=config_path)
    # Pin BEFORE the import: the inherited shell value is stale.
    os.environ["IDADIR"] = home
    try:
        import idapro  # noqa: PLC0415 - deliberately after the IDADIR pin
        import idaapi  # noqa: PLC0415
        import idc  # noqa: PLC0415
        import idautils  # noqa: PLC0415
    except ImportError as exc:
        _IDA_IMPORT_ERROR = exc
        raise IDAUnavailable(
            f"cannot import the IDA API with IDADIR={home!r}: {exc}"
        ) from exc

    # idalib's python directory may not be on sys.path before idapro loads it.
    _IDA_MODULES = {
        "idapro": idapro,
        "idaapi": idaapi,
        "idc": idc,
        "idautils": idautils,
    }
    return dict(_IDA_MODULES)


def wait_for_auto_analysis(modules: Mapping[str, Any] | None = None) -> bool:
    """Best-effort wait for IDA's auto-analysis to finish; True when it is done.

    ``idaapi.auto_is_ok()`` / ``idaapi.auto_wait()`` are absent from very old
    builds and from idalib before a database is open — then this is a no-op
    returning ``True`` rather than an error.
    """
    idaapi = (modules or {}).get("idaapi")
    if idaapi is None:
        return True
    try:
        if bool(idaapi.auto_is_ok()):
            return True
    except Exception:  # pragma: no cover - API absent
        return True
    try:
        idaapi.auto_wait()
    except Exception:  # pragma: no cover - API absent
        return False
    try:
        return bool(idaapi.auto_is_ok())
    except Exception:  # pragma: no cover - API absent
        return False


# ---------------------------------------------------------------------------
# decompiler (U-IDA3) — per-function text, or a schema-legal failure sentinel
# ---------------------------------------------------------------------------
def _sentinel(reason: str) -> str:
    """``DECOMPILE_FAILED(<reason>)`` — the schema-legal decompile failure marker.

    Matches ``schema.DECOMPILE_FAILED_RE`` by construction: lowercased, with every
    character outside ``[a-z0-9_]`` replaced by ``_``.
    """
    text = str(reason or "unknown").strip().lower()
    safe = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in text)
    return f"DECOMPILE_FAILED({safe or 'unknown'})"


def init_hexrays(modules: Mapping[str, Any] | None = None) -> Any | None:
    """Import and initialize ``ida_hexrays`` **exactly once**; ``None`` if absent.

    This is the only ``ida_hexrays`` import in the package and it happens at run
    time, so importing ``icepick.extract`` stays IDA-free.  Every failure mode — no
    module, no plugin, no licence, an exception out of ``init_hexrays_plugin()`` —
    degrades to ``None``; the caller turns that into a per-function ``failed``
    sentinel instead of an error, because a missing decompiler must never kill the
    emit.  ``modules`` may carry a pre-imported ``ida_hexrays`` (tests, hosted IDA);
    otherwise the module is imported here.
    """
    global _HEXRAYS_MODULE, _HEXRAYS_READY
    if _HEXRAYS_READY is not None:
        return _HEXRAYS_MODULE
    _HEXRAYS_READY = False  # "tried": a second call is a no-op even on failure
    module = dict(modules or _IDA_MODULES).get("ida_hexrays")
    if module is None:
        try:
            import ida_hexrays  # noqa: PLC0415 - deferred: only a live IDA has it
        except Exception:  # ImportError on the bridge, anything else inside IDA
            return None
        module = ida_hexrays
    try:
        ready = bool(module.init_hexrays_plugin())
    except Exception:  # noqa: BLE001 - a broken plugin means "no decompiler"
        return None
    if not ready:
        return None
    _HEXRAYS_MODULE = module
    _HEXRAYS_READY = True
    return _HEXRAYS_MODULE


def _classify_decompile_error(exc: BaseException) -> tuple[None, str, str]:
    """Map a hexrays exception to ``(None, status, sentinel)``.

    hexrays reports budget problems by raising rather than by returning a code, so
    the message is classified: time first (a timeout that merely mentions memory
    must not read as ``too_big``), then size, else ``failed``.
    """
    message = f"{type(exc).__name__}: {exc}".lower()
    if any(marker in message for marker in _DECOMPILE_TIMEOUT_MARKERS):
        return None, "timeout", _sentinel("timeout")
    if any(marker in message for marker in _DECOMPILE_TOO_BIG_MARKERS):
        return None, "too_big", _sentinel("too_big")
    return None, "failed", _sentinel(type(exc).__name__)


def decompile_func(
    ea: int,
    modules: Mapping[str, Any] | None = None,
    *,
    size: int | None = None,
    max_chars: int = DECOMPILE_TEXT_MAX_CHARS,
) -> tuple[str | None, str, str | None]:
    """Decompile one function; **never raises**.

    Returns ``(text, status, error)`` with ``status`` one of
    :data:`DECOMPILE_STATUSES`:

    ``ok``
        the decompiler returned non-empty text (``error`` is ``None``);
    ``too_big``
        the function exceeds :data:`DECOMPILE_TOO_BIG_BYTES` (the decompiler is then
        never called), the text exceeds ``max_chars``, or hexrays refused it for
        size;
    ``timeout``
        hexrays gave up on time;
    ``failed``
        anything else — no decompiler, ``None`` result, empty text, hexrays
        refusal, a broken plugin.

    Every non-``ok`` outcome carries a schema-legal ``DECOMPILE_FAILED(<reason>)``
    sentinel in ``error``, so the caller can always emit a validating record.
    """
    try:
        too_big = size is not None and int(size) > DECOMPILE_TOO_BIG_BYTES
    except (TypeError, ValueError):  # pragma: no cover - defensive
        too_big = False
    if too_big:
        return None, "too_big", _sentinel("too_big")

    module = init_hexrays(modules)
    if module is None:
        return None, "failed", _sentinel("hexrays_unavailable")

    try:
        cfunc = module.decompile(int(ea))
    except Exception as exc:  # noqa: BLE001 - one function must not kill the emit
        return _classify_decompile_error(exc)
    if cfunc is None:
        return None, "failed", _sentinel("decompile_returned_none")
    try:
        text = str(cfunc)
    except Exception:  # noqa: BLE001 - broken cfunc_t
        return None, "failed", _sentinel("text_extraction_failed")
    if not text.strip():
        return None, "failed", _sentinel("empty_text")
    if len(text) > max_chars:
        return None, "too_big", _sentinel("too_big")
    return text, "ok", None


def open_idb(
    target: Any,
    *,
    ida_home: str | None = None,
    trust_env: bool = False,
    run_auto_analysis: bool = True,
) -> tuple[dict[str, Any], bool]:
    """Open ``target`` for extraction; returns ``(modules, we_opened_it)``.

    Hosted IDA context is tried first; anywhere else the idalib lane runs
    ``idapro.open_database`` with auto-analysis and waits for it to complete.
    """
    try:
        return _hosted_modules(), False
    except IDANotHosted:
        pass

    modules = import_ida(ida_home=ida_home, trust_env=trust_env)
    idapro = modules["idapro"]
    code = idapro.open_database(str(target), bool(run_auto_analysis))
    if code != 0:
        raise ExtractError(
            f"idapro.open_database({str(target)!r}, run_auto_analysis="
            f"{bool(run_auto_analysis)}) failed with code {code}"
        )
    wait_for_auto_analysis(modules)
    return modules, True


def close_idb(modules: Mapping[str, Any] | None, *, save: bool = False) -> None:
    """Close a database this process opened; ``save=False`` (extraction is read-only)."""
    idapro = (modules or {}).get("idapro")
    close = getattr(idapro, "close_database", None)
    if callable(close):
        close(bool(save))


@contextmanager
def analysis_context(
    target: Any,
    *,
    ida_home: str | None = None,
    trust_env: bool = False,
    run_auto_analysis: bool = True,
):
    """Yield a :class:`World` for ``target``, closing an IDB we opened ourselves."""
    modules, opened = open_idb(
        target,
        ida_home=ida_home,
        trust_env=trust_env,
        run_auto_analysis=run_auto_analysis,
    )
    try:
        yield RealIdaWorld(modules)
    finally:
        if opened:
            close_idb(modules)


def func_lib_mask(idaapi: Any = None) -> int:
    """``func_t::flags`` mask marking a library (FLIRT) function.

    Read from ``idaapi.FUNC_LIB`` when IDA is loaded; otherwise the pinned SDK
    value is used.
    """
    if idaapi is not None:
        value = getattr(idaapi, "FUNC_LIB", None)
        if isinstance(value, int):
            return value
    return FUNC_LIB_FALLBACK


def _func_flag_bits(idaapi: Any = None) -> tuple[tuple[str, int], ...]:
    if idaapi is None:
        return FUNC_FLAG_BITS
    resolved: list[tuple[str, int]] = []
    for name, default in FUNC_FLAG_BITS:
        value = getattr(idaapi, f"FUNC_{name.upper()}", default)
        resolved.append((name, int(value) if isinstance(value, int) else default))
    return tuple(resolved)


def flag_names(flags: int, *, is_flirt: bool = False, idaapi: Any = None) -> list[str]:
    """Sorted textual names for the set ``func_t::flags`` bits (+ explicit ``flirt``)."""
    names = {name for name, bit in _func_flag_bits(idaapi) if flags & bit}
    if is_flirt:
        names.add("flirt")
    return sorted(names)


def _xref_kind(xref: Any, idaapi: Any) -> str:
    """Classify an IDA xref object into :data:`XREF_KINDS`."""
    if not bool(getattr(xref, "iscode", False)):
        return "data"
    kind = getattr(xref, "type", None)
    if kind is None:
        return "unknown"
    calls = {getattr(idaapi, name, None) for name in _CALL_XREF_NAMES}
    jumps = {getattr(idaapi, name, None) for name in _JUMP_XREF_NAMES}
    if kind in calls:
        return "call"
    if kind in jumps:
        return "jump"
    return "unknown"


# ---------------------------------------------------------------------------
# the world adapter: every IDA call site in the package lives in RealIdaWorld
# ---------------------------------------------------------------------------
class World(Protocol):
    """Read-only view of an analysed database (implemented by the IDA adapter).

    ``emit`` only ever calls these methods, which is what makes the document
    builder testable without an IDA runtime.
    """

    def func_eas(self) -> Iterable[int]:
        """Start addresses of every defined function."""

    def func_name(self, ea: int) -> str:
        """Current name of the function at ``ea``."""

    def func_flags(self, ea: int) -> int:
        """Raw ``func_t::flags`` of the function at ``ea``."""

    def func_size(self, ea: int) -> int:
        """Byte size of the function at ``ea``."""

    def func_demangled(self, ea: int) -> str | None:
        """Demangled name, or ``None`` (best effort)."""

    def func_prototype(self, ea: int) -> str | None:
        """Type/prototype string, or ``None`` (best effort)."""

    def block_eas(self, ea: int) -> Sequence[int]:
        """Basic block start addresses of the CFG (best effort sorted list)."""

    def xrefs_to(self, ea: int) -> Sequence[tuple[int, str]]:
        """``(from_ea, kind)`` for every reference *to* ``ea``."""

    def xrefs_from(self, ea: int) -> Sequence[tuple[int, str]]:
        """``(to_ea, kind)`` for every reference *from* ``ea``."""

    def func_lib_mask(self) -> int:
        """Mask marking a library (FLIRT) function — ``idaapi.FUNC_LIB``."""

    def auto_analysis_ok(self) -> bool:
        """True when IDA considers auto-analysis complete."""

    def ida_version(self) -> str:
        """IDA kernel version string, e.g. ``"9.5.0.250616"``."""

    def idb_path(self) -> str | None:
        """Path of the open database, if IDA reports one."""

    def input_path(self) -> str | None:
        """Path of the analysed input binary, if IDA reports one."""

    def decompile(self, ea: int) -> tuple[str | None, str, str | None]:
        """Decompiler text for ``ea``: ``(text|None, status, error|None)``.

        Best effort and never raising: the status is always one of
        :data:`DECOMPILE_STATUSES` and ``error`` carries a
        ``DECOMPILE_FAILED(<reason>)`` sentinel whenever the text is ``None``
        (see :func:`decompile_func`).
        """

    def rtti_refs(self, ea: int) -> Sequence[int]:
        """Effective addresses of RTTI/vtable data ``ea`` refers to (best effort)."""

    def pdb_type(self, ea: int) -> str | None:
        """PDB-derived type name for ``ea``, or ``None`` (best effort)."""


class RealIdaWorld:
    """The only implementation of :class:`World` that touches IDA.

    Constructed with the module dict from :func:`import_ida`; it is created
    lazily by ``emit``/``main`` and never at import time, so importing
    ``icepick.extract`` stays IDA-free.
    """

    def __init__(
        self,
        modules: Mapping[str, Any] | None = None,
        *,
        ida_home: str | None = None,
        trust_env: bool = False,
    ) -> None:
        self._modules = dict(modules) if modules is not None else import_ida(
            ida_home=ida_home, trust_env=trust_env
        )
        self._idaapi = self._modules["idaapi"]
        self._idc = self._modules["idc"]
        self._idautils = self._modules["idautils"]

    # -- function inventory -------------------------------------------------
    def func_eas(self) -> list[int]:
        return sorted(int(ea) for ea in self._idautils.Functions())

    def func_name(self, ea: int) -> str:
        return str(self._idc.get_func_name(ea) or "")

    def func_flags(self, ea: int) -> int:
        func = self._idaapi.get_func(ea)
        return int(getattr(func, "flags", 0)) if func is not None else 0

    def func_size(self, ea: int) -> int:
        func = self._idaapi.get_func(ea)
        if func is None:
            return 0
        size = getattr(func, "size", None)
        if callable(size):
            try:
                return int(size())
            except Exception:  # pragma: no cover - broken func_t
                pass
        end = int(getattr(func, "end_ea", 0) or 0)
        start = int(getattr(func, "start_ea", 0) or 0)
        return max(0, end - start)

    def func_demangled(self, ea: int) -> str | None:
        name = self.func_name(ea)
        if not name:
            return None
        try:
            demangled = self._idc.demangle_name(
                name, self._idc.get_inf_attr(self._idc.INF_SHORT_DN)
            )
        except Exception:  # pragma: no cover - API absent
            return None
        return str(demangled) if demangled else None

    def func_prototype(self, ea: int) -> str | None:
        try:
            prototype = self._idc.get_type(ea)
        except Exception:  # pragma: no cover - API absent
            return None
        return str(prototype) if prototype else None

    # -- CFG ----------------------------------------------------------------
    def block_eas(self, ea: int) -> list[int]:
        func = self._idaapi.get_func(ea)
        if func is None:
            return []
        try:
            flags = getattr(self._idaapi, "FC_PREDS", 0)
            chart = self._idaapi.FlowChart(func, flags=flags)
            return sorted({int(block.start_ea) for block in chart})
        except Exception:  # pragma: no cover - broken CFG
            return []

    # -- xrefs --------------------------------------------------------------
    def _xrefs(self, ea: int, *, incoming: bool) -> list[tuple[int, str]]:
        xref_all = getattr(self._idaapi, "XREF_ALL", 0)
        iterate = (
            self._idautils.XrefsTo(ea, xref_all)
            if incoming
            else self._idautils.XrefsFrom(ea, xref_all)
        )
        out: list[tuple[int, str]] = []
        for xref in iterate:
            other = getattr(xref, "frm" if incoming else "to", None)
            if other is None:
                continue
            out.append((int(other), _xref_kind(xref, self._idaapi)))
        return out

    def xrefs_to(self, ea: int) -> list[tuple[int, str]]:
        return self._xrefs(ea, incoming=True)

    def xrefs_from(self, ea: int) -> list[tuple[int, str]]:
        return self._xrefs(ea, incoming=False)

    # -- provenance ---------------------------------------------------------
    def func_lib_mask(self) -> int:
        return func_lib_mask(self._idaapi)

    def auto_analysis_ok(self) -> bool:
        return wait_for_auto_analysis(self._modules)

    def ida_version(self) -> str:
        try:
            version = self._idaapi.get_kernel_version()
        except Exception:  # pragma: no cover - API absent
            return UNKNOWN_IDA_VERSION
        return str(version or UNKNOWN_IDA_VERSION)

    def idb_path(self) -> str | None:
        try:
            path = self._idc.get_idb_path()
        except Exception:  # pragma: no cover - API absent
            return None
        return str(path) if path else None

    def input_path(self) -> str | None:
        try:
            path = self._idaapi.get_input_file_path()
        except Exception:  # pragma: no cover - API absent
            return None
        return str(path) if path else None

    # -- decompiler / RTTI / PDB types (U-IDA3, all best effort) -------------
    def decompile(self, ea: int) -> tuple[str | None, str, str | None]:
        """Per-function decompiler text via :func:`decompile_func` (never raises)."""
        return decompile_func(ea, self._modules, size=self.func_size(ea))

    def _name_at(self, ea: int) -> str:
        try:
            return str(self._idc.get_name(ea) or "")
        except Exception:  # pragma: no cover - API absent
            return ""

    def _first_ref_from(self, ea: int) -> int | None:
        """First target ``ea`` refers to (best effort) — one vtable slot, say."""
        try:
            for xref in self._idautils.XrefsFrom(ea, 0):
                target = getattr(xref, "to", None)
                if target is not None:
                    return int(target)
        except Exception:  # pragma: no cover - API absent
            return None
        return None

    def rtti_refs(self, ea: int) -> list[int]:
        """RTTI/vtable addresses reachable from ``ea`` (best effort; ``[]`` if none).

        A reference counts when its target is *named* like an RTTI artefact
        (``??_7`` vftable, ``??_R0`` type descriptor, ``_ZTV``/``_ZTI``,
        ``vftable``/``vtable``/``type_info``) or when it points at a slot holding
        one — the usual ``lea reg, [vftable]`` shape.  Speculative by design:
        missing RTTI yields ``[]``, never an error.
        """
        try:
            xref_all = getattr(self._idaapi, "XREF_ALL", 0)
            targets = [
                getattr(xref, "to", None)
                for xref in self._idautils.XrefsFrom(ea, xref_all)
            ]
        except Exception:  # pragma: no cover - API absent
            return []
        refs: set[int] = set()
        for target in targets:
            if target is None:
                continue
            target = int(target)
            if _looks_like_rtti_name(self._name_at(target)):
                refs.add(target)
                continue
            inner = self._first_ref_from(target)
            if inner is not None and _looks_like_rtti_name(self._name_at(inner)):
                refs.add(inner)
        return sorted(refs)

    def pdb_type(self, ea: int) -> str | None:
        """Named (often PDB-imported) type of ``ea``, or ``None`` (best effort).

        ``tinfo_t::get_type_name`` yields the *named* type only: a type imported
        without a name reads as absent (``""`` in the document) rather than as an
        invented one.
        """
        try:
            import ida_typeinf  # noqa: PLC0415 - IDA-only, deferred
        except Exception:  # pragma: no cover - hosted-only API
            return None
        try:
            tif = ida_typeinf.tinfo_t()
            if not self._idaapi.get_tinfo(tif, int(ea)):
                return None
            name = tif.get_type_name()
        except Exception:  # pragma: no cover - API absent
            return None
        return str(name) if name else None

    def apply_sigs(self, sig_files: Sequence[str]) -> int:
        """Best-effort FLIRT application; returns files scheduled, never raises.

        Only names pointing at existing files are offered to IDA
        (``ida_funcs.plan_to_apply_idasgn`` when the API is present); anything
        else — absent API, missing file, hosted quirks — degrades to
        record-only, which is why provenance always carries the names.
        """
        try:
            ida_funcs = self._modules.get("ida_funcs")
            if ida_funcs is None:
                try:
                    import ida_funcs  # noqa: PLC0415 - IDA-only, deferred
                except Exception:
                    return 0
            schedule = getattr(ida_funcs, "plan_to_apply_idasgn", None)
            if not callable(schedule):
                return 0
            applied = 0
            for sig in sig_files:
                path = str(sig)
                if not path or not os.path.isfile(path):
                    continue
                try:
                    schedule(path)
                    applied += 1
                except Exception:
                    continue
            return applied
        except Exception:
            return 0


def _apply_sigs_best_effort(world: Any, sig_files: Sequence[str]) -> int:
    """Ask ``world`` to apply sig files; record-only when unsupported.

    Never raises: a world without the hook (including every fake world in the
    test suite) simply records the names in provenance.
    """
    try:
        hook = getattr(world, "apply_sigs", None)
        if callable(hook):
            result = hook(list(sig_files))
            return int(result) if result is not None else 0
    except Exception:
        pass
    return 0


# ---------------------------------------------------------------------------
# pure document building
# ---------------------------------------------------------------------------
def sha256_file(path: Any, *, chunk_size: int = 1 << 20) -> str:
    """Streaming sha256 of a file (64 lowercase hex characters)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


def idb_sha256(world: World) -> str:
    """Content hash identifying the analysed database.

    Preference: the IDB/``.i64`` file → the analysed input binary → a sha256 of
    the IDB path string.  The last resort is stable and determinism-friendly but
    is explicitly *not* a content hash (documented on the document's
    ``provenance.idb_sha256``).
    """
    idb_path = _call_text(world, "idb_path")
    input_path = _call_text(world, "input_path")
    for candidate in (idb_path, input_path):
        if candidate and os.path.isfile(candidate):
            return sha256_file(candidate)
    seed = idb_path or input_path or ""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _call_text(world: World, name: str, *args: Any) -> str | None:
    """Best-effort optional probe: callable? value → trimmed non-empty string?"""
    method = getattr(world, name, None)
    if not callable(method):
        return None
    try:
        value = method(*args)
    except Exception:
        return None
    text = "" if value is None else str(value).strip()
    return text or None


def _looks_like_rtti_name(name: Any) -> bool:
    """True when ``name`` is spelled like an RTTI/vtable artefact."""
    text = str(name or "").strip().lower()
    if not text:
        return False
    return any(marker in text for marker in _RTTI_NAME_MARKERS)


#: Demangled MSVC RTTI/vtable artefact spellings (compared lowercased).
_RTTI_NAME_MARKERS: tuple[str, ...] = (
    "vftable",
    "vbtable",
    "vcall",
    "rtti",
    "type descriptor",
    "class hierarchy",
    "object locator",
)


def _call_eas(world: World, name: str, *args: Any) -> list[int]:
    """Best-effort list-of-EA probe: absent or raising yields ``[]`` (never raises)."""
    method = getattr(world, name, None)
    if not callable(method):
        return []
    try:
        values = method(*args)
    except Exception:
        return []
    eas: set[int] = set()
    try:
        for value in values or ():
            ea = schema.parse_ea(value)
            if ea is not None:
                eas.add(ea)
    except Exception:  # pragma: no cover - a hostile iterable
        return sorted(eas)
    return sorted(eas)


def _decompile_probe(world: World, ea: int) -> tuple[str | None, str, str]:
    """One function's ``(text, status, error)`` — never raises, always schema-legal.

    A world with no ``decompile`` member (the U-IDA2 fakes) means "no decompiler
    here": :data:`DECOMPILE_NOT_ATTEMPTED` keeps its record valid instead of
    inventing text or dropping the function.  Anything the probe throws — including
    a malformed return value — becomes a ``failed`` sentinel, because one
    function's failure must never kill the emit.
    """
    method = getattr(world, "decompile", None)
    if not callable(method):
        return None, "failed", DECOMPILE_NOT_ATTEMPTED
    try:
        text, status, error = method(ea)
    except Exception as exc:
        return None, "failed", _sentinel(type(exc).__name__)

    text = text if isinstance(text, str) and text.strip() else None
    status = status if status in DECOMPILE_STATUSES else "failed"
    if text is None:
        if not (isinstance(error, str) and schema.DECOMPILE_FAILED_RE.match(error)):
            error = _sentinel("failed" if status == "failed" else status)
        if status == "ok":
            status = "failed"
        return None, status, error
    if len(text) > DECOMPILE_TEXT_MAX_CHARS:
        return None, "too_big", _sentinel("too_big")
    return text, "ok", None


def _clean_name(name: Any, ea: int) -> str:
    """Schema-safe function name: non-empty, no whitespace/control chars, capped.

    IDA can hand back an empty name (or, in theory, one with whitespace); the
    document must stay valid, so such names are normalised rather than emitted
    as-is.  Deterministic: the same input always yields the same output.
    """
    text = str(name or "").strip()
    if not text:
        text = f"sub_{ea:x}"
    if not schema.NAME_RE.match(text):
        text = "".join(
            "_" if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F else ch
            for ch in text
        )
        if not schema.NAME_RE.match(text):
            text = f"sub_{ea:x}"
    return text[: schema.NAME_MAX_LEN]


def _norm_kind(kind: Any) -> str:
    text = str(kind or "").strip().lower()
    return text if text in XREF_KINDS else "unknown"


def _sorted_xrefs(entries: Iterable[tuple[int, str]]) -> list[dict[str, Any]]:
    """De-duplicated ``[{"ea": .., "kind": ..}]`` sorted by ``(ea, kind)``."""
    pairs = {(int(ea), _norm_kind(kind)) for ea, kind in entries}
    return [{"ea": ea, "kind": kind} for ea, kind in sorted(pairs)]


def _cap(values: list[Any], top_k: int, field: str, truncated: list[str]) -> list[Any]:
    """Truncate ``values`` to ``top_k`` and record the field name when it bites."""
    if len(values) > top_k:
        truncated.append(field)
        return values[:top_k]
    return list(values)


def _count(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0
    return number if number > 0 else 0


def _world_func_lib_mask(world: World) -> int:
    mask = getattr(world, "func_lib_mask", None)
    if callable(mask):
        try:
            return int(mask())
        except Exception:  # pragma: no cover - defensive
            return FUNC_LIB_FALLBACK
    return FUNC_LIB_FALLBACK


def _func_bounds(world: World, eas: set[int]) -> dict[int, int]:
    """``{func_start: func_end_exclusive}`` for call-site containment mapping."""
    bounds: dict[int, int] = {}
    for ea in eas:
        try:
            size = int(world.func_size(ea) or 0)
        except Exception:
            size = 0
        bounds[ea] = ea + max(size, 1)
    return bounds


def _owner_of(
    bounds: Mapping[int, int], starts: list[int], addr: int
) -> int | None:
    """Start address of the function containing ``addr`` (padding → ``None``)."""
    index = bisect.bisect_right(starts, int(addr)) - 1
    if index < 0:
        return None
    start = starts[index]
    return start if int(addr) < bounds[start] else None


def _func_record(
    world: World,
    ea: int,
    top_k: int,
    known_eas: set[int],
    owner: Any = None,
) -> tuple[dict[str, Any], set[tuple[int, int, str]]]:
    """One schema-v1 function record plus the call edges it contributes.

    ``owner`` maps a call-site instruction address to its containing function
    start (``None`` for padding/foreign code); raw xref detail is always kept
    in ``xrefs_to``/``xrefs_from``, while ``callers`` holds function starts and
    ``callees`` are completed by inversion in :func:`emit` (a call can sit
    mid-function, so entry-address xrefs alone never see the full picture).
    """
    flags = int(world.func_flags(ea) or 0)
    is_flirt = bool(flags & _world_func_lib_mask(world))
    truncated: list[str] = []

    block_eas = sorted({int(block) for block in world.block_eas(ea)})
    block_count = len(block_eas)
    shown_blocks = _cap(block_eas, top_k, "block_eas", truncated)

    xrefs_to = _sorted_xrefs(world.xrefs_to(ea))
    xrefs_from = _sorted_xrefs(world.xrefs_from(ea))
    shown_to = _cap(xrefs_to, top_k, "xrefs_to", truncated)
    shown_from = _cap(xrefs_from, top_k, "xrefs_from", truncated)

    raw_callers = [
        int(item["ea"]) for item in xrefs_to if item["kind"] == "call"
    ]
    if owner is None:
        callers = sorted({ea for ea in raw_callers if ea in known_eas})
    else:
        callers = sorted(
            {
                mapped
                for site in raw_callers
                for mapped in [owner(site)]
                if mapped is not None and mapped in known_eas
            }
        )
    raw_callees = [
        int(item["ea"]) for item in xrefs_from if item["kind"] == "call"
    ]
    if owner is None:
        seed_callees = sorted({ea for ea in raw_callees if ea in known_eas})
    else:
        seed_callees = sorted(
            {
                mapped
                for site in raw_callees
                for mapped in [owner(site)]
                if mapped is not None and mapped in known_eas
            }
        )
    shown_callers = _cap(callers, top_k, "callers", truncated)
    shown_callees = _cap(seed_callees, top_k, "callees", truncated)

    edges = {(src, ea, "call") for src in callers if src in known_eas}

    decompiled, decompile_status, decompile_error = _decompile_probe(world, ea)
    rtti_refs = _cap(_call_eas(world, "rtti_refs", ea), top_k, "rtti_refs", truncated)
    pdb_type = _call_text(world, "pdb_type", ea) or ""

    record: dict[str, Any] = {
        "ea": ea,
        "name": _clean_name(world.func_name(ea), ea),
        "name_source": "flirt" if is_flirt else "ida",
        "is_flirt": is_flirt,
        "demangled": _call_text(world, "func_demangled", ea),
        "prototype": _call_text(world, "func_prototype", ea),
        "flags": flag_names(flags, is_flirt=is_flirt),
        "size": _count(world.func_size(ea)),
        "blocks": block_count,
        "block_eas": shown_blocks,
        "callers": shown_callers,
        "callees": shown_callees,
        "xrefs_to": shown_to,
        "xrefs_from": shown_from,
        "truncated": truncated,
        # U-IDA3: decompiler text when the decompiler produced some, else a sentinel
        # that never kills the emit; RTTI/vtable refs and the PDB type name are best
        # effort and empty when absent.
        "decompiled": decompiled,
        "decompile_status": decompile_status,
        "decompile_error": decompile_error,
        "rtti_refs": rtti_refs,
        "pdb_type": pdb_type,
    }
    return record, edges


def emit(
    world: World | None = None,
    *,
    top_k: int = DEFAULT_TOP_K,
    backend: str = "idalib",
    auto_analysis: bool | None = None,
    sigs: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Build a schema-v1 extract document for ``world`` (IDA by default).

    The returned dict is guaranteed to pass :func:`icepick.schema.validate_extract`
    — it is validated here and an :class:`ExtractError` is raised instead of
    returning a document the bridge would reject downstream.  Functions are
    sorted by ``ea``, every list is sorted and capped at ``top_k`` (default
    :data:`DEFAULT_TOP_K`), and nothing about the host leaks into the output.
    """
    if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k < 1:
        raise ExtractError(f"top_k must be a positive integer, got {top_k!r}")
    if backend not in schema.BACKENDS:
        raise ExtractError(
            f"backend must be one of {', '.join(repr(b) for b in schema.BACKENDS)}; "
            f"got {backend!r}"
        )
    if world is None:
        world = RealIdaWorld()

    sig_names = [str(s).strip() for s in (sigs or []) if str(s).strip()]
    _apply_sigs_best_effort(world, sig_names)

    known_eas = {int(ea) for ea in world.func_eas()}
    if not known_eas:
        raise ExtractError(
            "extract produced no functions: the database holds no defined "
            "functions (an unanalysed input, or a stub binary that analyzes to "
            "zero functions)"
        )

    bounds = _func_bounds(world, known_eas)
    starts = sorted(bounds)

    def owner(addr: int) -> int | None:
        return _owner_of(bounds, starts, addr)

    funcs: list[dict[str, Any]] = []
    edge_keys: set[tuple[int, int, str]] = set()
    for ea in sorted(known_eas):
        record, edges = _func_record(world, ea, top_k, known_eas, owner)
        funcs.append(record)
        edge_keys |= edges
    by_ea = {record["ea"]: record for record in funcs}
    for record in funcs:
        for caller in record["callers"]:
            target = by_ea.get(caller)
            if target is not None and record["ea"] not in target["callees"]:
                target["callees"].append(record["ea"])
                if len(target["callees"]) > top_k and "callees" not in target[
                    "truncated"
                ]:
                    target["truncated"].append("callees")
    for record in funcs:
        record["callees"] = sorted(set(record["callees"]))[:top_k]
        edge_keys |= {
            (caller, record["ea"], "call")
            for caller in record["callers"]
            if caller in by_ea
        }
    funcs.sort(key=lambda func: func["ea"])

    if auto_analysis is None:
        probe = getattr(world, "auto_analysis_ok", None)
        auto_analysis = bool(probe()) if callable(probe) else True

    version = _call_text(world, "ida_version") or UNKNOWN_IDA_VERSION
    generator = f"{GENERATOR} ({backend})"
    document: dict[str, Any] = {
        "schema_version": schema.SCHEMA_VERSION,
        "kind": "extract",
        "doc_source": "ida",
        "generator": generator,
        "provenance": {
            "ida_version": version,
            "idb_sha256": idb_sha256(world),
            "auto_analysis": bool(auto_analysis),
            "backend": backend,
            "generator": generator,
            "sigs_applied": [{"name": name} for name in sig_names],
        },
        "funcs": funcs,
        "edges": [
            {"src": src, "dst": dst, "kind": kind}
            for src, dst, kind in sorted(edge_keys)
        ],
    }

    errors = schema.validate_extract(document)
    if errors:  # pragma: no cover - guarded by the code above
        raise ExtractError(
            f"internal error: emitted document failed validation "
            f"({len(errors)} problem(s)):\n  - " + "\n  - ".join(errors)
        )
    return document


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
    """Add the extraction flags to ``parser`` (shared with ``icepick extract``)."""
    parser.add_argument(
        "target",
        metavar="INPUT",
        help="input binary (or IDB/IDC) to analyse; the hosted database is used when "
        "running inside IDA",
    )
    parser.add_argument(
        "-o",
        "--out",
        metavar="OUT",
        default=None,
        help="write the extract JSON here (default: stdout)",
    )
    parser.add_argument(
        "--top-k",
        dest="top_k",
        type=int,
        default=DEFAULT_TOP_K,
        metavar="N",
        help=f"cap each xref/caller/callee/CFG list at N entries (default: {DEFAULT_TOP_K})",
    )
    parser.add_argument(
        "--backend",
        choices=list(schema.BACKENDS),
        default=None,
        help="provenance backend tag (default: idat when hosted, idalib standalone)",
    )
    parser.add_argument(
        "--ida-home",
        dest="ida_home",
        metavar="DIR",
        default=None,
        help="IDA install directory to pin as IDADIR (default: ida-config.json)",
    )
    parser.add_argument(
        "--trust-env-idadir",
        dest="trust_env_idadir",
        action="store_true",
        help="trust the inherited IDADIR (ignored by default: a harness shell's value is stale)",
    )
    parser.add_argument(
        "--apply-names",
        dest="apply_names",
        action="store_true",
        help="not implemented: extraction is read-only and never writes the IDB",
    )
    parser.add_argument(
        "--sigs",
        dest="sigs",
        metavar="SIG",
        action="append",
        default=None,
        help="private FLIRT signature file to apply (repeatable); names are "
        "recorded in provenance.sigs_applied and application is best-effort",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="write the document but print nothing on success",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Standalone parser for ``python -m icepick.extract``."""
    parser = argparse.ArgumentParser(
        prog=f"{PROGRAM} extract",
        description=(
            "Extract a deterministic schema-v1 inventory from an IDB (or from the "
            "database IDA already has open) and write it as JSON."
        ),
    )
    return add_arguments(parser)


def _coerce_args(argv: Any = None) -> argparse.Namespace:
    """Accept either a pre-parsed namespace (from ``icepick extract``) or argv."""
    if isinstance(argv, argparse.Namespace):
        return argv
    raw = list(argv) if argv is not None else None
    if raw:
        # Allow the ``extract`` token so ``main(["extract", ...])`` also works.
        raw = [token for token in raw] if raw[0] != "extract" else raw[1:]
    return build_parser().parse_args(raw)


def _fail(message: str) -> int:
    print(f"{PROGRAM}: extract: {message}", file=sys.stderr)
    return 1


def main(argv: Any = None, *, world: World | None = None) -> int:
    """``icepick extract`` entry point; returns the process exit code.

    ``world`` is a test seam: pass a fake :class:`World` to exercise the whole
    lane (validation, deterministic JSON, file writing) with no IDA runtime.
    """
    args = _coerce_args(argv)
    target = getattr(args, "target", None)
    top_k = getattr(args, "top_k", DEFAULT_TOP_K)
    out = getattr(args, "out", None)
    quiet = bool(getattr(args, "quiet", False))
    sigs = getattr(args, "sigs", None)

    if getattr(args, "apply_names", False):
        print(
            f"{PROGRAM}: extract: --apply-names is not implemented: extraction is "
            "read-only (U-IDA2 never writes names into the IDB)",
            file=sys.stderr,
        )
        return 2
    if not target:
        print(f"{PROGRAM}: extract: an INPUT path is required", file=sys.stderr)
        return 2

    path = Path(str(target))
    if not path.exists():
        return _fail(f"no such input: {path}")

    backend = getattr(args, "backend", None)
    if backend is None:
        backend = "idat" if is_hosted() else "idalib"

    try:
        if world is not None:
            document = emit(world, top_k=top_k, backend=backend, sigs=sigs)
        else:
            with analysis_context(
                path,
                ida_home=getattr(args, "ida_home", None),
                trust_env=bool(getattr(args, "trust_env_idadir", False)),
            ) as live:
                document = emit(live, top_k=top_k, backend=backend, sigs=sigs)
    except (ExtractError, IDAHomeError, IDAUnavailable, IDANotHosted, OSError) as exc:
        return _fail(str(exc))

    text = dumps_document(document)
    if out in (None, "-"):
        sys.stdout.write(text)
        return 0

    destination = Path(str(out))
    if not destination.parent.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" keeps the bytes identical on every platform.
    destination.write_text(text, encoding="utf-8", newline="\n")
    if not quiet:
        print(
            f"{PROGRAM}: extract: wrote {destination} "
            f"({len(document['funcs'])} funcs, {len(document['edges'])} edges)"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
