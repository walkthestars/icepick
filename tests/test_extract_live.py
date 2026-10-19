"""Live extraction lane — two real subprocesses must emit byte-identical JSON.

This is the U-IDA2 accept criterion (``docs/UNIT-IDA-PLAN.md``): *byte-identical
JSON across two runs on a target IDA actually analyzes*.  It is the only test in
the suite that needs a real IDA install, so it is **skipped, never failed**, when
the environment cannot support it:

* no ``idapro`` module in the interpreter running the test  → skip;
* no resolvable IDA install directory (``ida-config.json`` / ``IDADIR``) → skip;
* no small host PE to analyse (``C:\\Windows\\System32\\whoami.exe`` by default)
  → skip;
* the child itself reports that IDA is unavailable or unlicensed → skip.

When all of that is present the test is strict: it runs ``python -m icepick
extract`` **twice**, in two separate child processes (a fresh IDA process each
time, so nothing can be carried over in memory), with ``IDADIR`` pinned to the
resolved install and ``PYTHONPATH`` pointing at ``src/``, and then asserts that

1. both children exit ``0``,
2. the two documents are byte-identical (and their canonical digests match),
3. :func:`icepick.schema.validate_extract` returns ``[]`` for the document,
4. the provenance names the ``idalib`` backend and a sha256 IDB digest, and
5. no host/runner detail (temp directory, output path, input file name) leaks
   into the document — that is what makes the output reproducible elsewhere.

The binary is copied into ``tmp_path`` first: extraction is read-only, but a test
must never point IDA at a system file in place, and a copied PE keeps the
analysed input inside the test's own directory.
"""

from __future__ import annotations

import functools
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from icepick import extract, schema

#: Repo root and the ``src/`` tree that ``PYTHONPATH`` must expose to the child.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

#: Small host PE to analyse when ``ICEPICK_TEST_PE`` is not set.
HOST_PE_CANDIDATES = (
    Path(r"C:\Windows\System32\whoami.exe"),
    Path(r"C:\Windows\SysWOW64\whoami.exe"),
)

#: Set ``ICEPICK_TEST_PE`` to analyse a different (small, real) PE.
HOST_PE_ENV = "ICEPICK_TEST_PE"

#: Optional explicit install directory (overrides ``ida-config.json``).
IDA_HOME_ENV = "ICEPICK_TEST_IDA_HOME"

#: Bounds: auto-analysis of a small PE is seconds; a hang must not eat the suite.
RUN_TIMEOUT_SECS = 900

#: A non-zero child run matching this is an environment limit, not a regression.
_UNAVAILABLE_RE = re.compile(
    r"IDAUnavailable|IDANotHosted|cannot import the IDA API|"
    r"no usable IDA install|licen[cs]e|open_database\(.*\) failed with code",
    re.IGNORECASE,
)


def _host_pe() -> Path | None:
    """The small host PE to copy, or ``None`` when none is available."""
    override = os.environ.get(HOST_PE_ENV)
    if override:
        candidate = Path(override)
        return candidate if candidate.is_file() else None
    for candidate in HOST_PE_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def _pinned_ida_home() -> str | None:
    """The install directory the child must pin as ``IDADIR``; ``None`` if unknown.

    Resolution is the pure, IDA-free half of :mod:`icepick.extract`, so a machine
    without IDA never reaches the expensive part: the answer comes from
    ``ICEPICK_TEST_IDA_HOME`` or ``ida-config.json`` (``Paths.ida-install-dir``).
    """
    override = os.environ.get(IDA_HOME_ENV)
    if override and extract.is_ida_install(override):
        return str(Path(override))
    try:
        return extract.resolve_ida_home()
    except extract.IDAHomeError:
        return None


_HAS_IDAPRO = importlib.util.find_spec("idapro") is not None
_HOST_PE = _host_pe()
_IDA_HOME = _pinned_ida_home() if _HAS_IDAPRO else None

# --------------------------------------------------------------------------
# module-level gate: skip — do not fail — when the environment cannot play
# --------------------------------------------------------------------------
_REASONS: list[str] = []
if not _HAS_IDAPRO:
    _REASONS.append(
        "idapro is not importable in this interpreter (no idalib install): the "
        "live extraction lane cannot run"
    )
elif _IDA_HOME is None:
    _REASONS.append(
        "no usable IDA install directory could be resolved (set "
        f"{IDA_HOME_ENV} or Paths.ida-install-dir in ida-config.json)"
    )
elif _HOST_PE is None:
    _REASONS.append(
        "no small host PE found (looked at "
        + ", ".join(str(path) for path in HOST_PE_CANDIDATES)
        + f"; set {HOST_PE_ENV} to point at one)"
    )

if _REASONS:
    pytest.skip("; ".join(_REASONS), allow_module_level=True)


def _child_env() -> dict[str, str]:
    """Child environment: pinned ``IDADIR`` + ``src/`` on ``PYTHONPATH``.

    ``IDADIR`` is set explicitly because a harness shell may carry a stale value
    (environment rule, ``docs/UNIT-IDA-PLAN.md``); ``PYTHONPATH`` guarantees the
    child imports this checkout of ``icepick`` and not an installed copy.
    """
    env = dict(os.environ)
    env[IDA_HOME_ENV] = str(_IDA_HOME)
    env["IDADIR"] = str(_IDA_HOME)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) if not existing else str(SRC) + os.pathsep + existing
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _run_extract(target: Path, out: Path) -> subprocess.CompletedProcess[str]:
    """Run ``python -m icepick extract`` in a fresh child process."""
    return subprocess.run(
        [sys.executable, "-m", "icepick", "extract", str(target), "--out", str(out)],
        cwd=str(ROOT),
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECS,
    )


def _skip_if_unavailable(result: subprocess.CompletedProcess[str]) -> None:
    """Turn an environment limit reported by the child into a skip."""
    if result.returncode == 0:
        return
    detail = (result.stderr or "") + (result.stdout or "")
    if _UNAVAILABLE_RE.search(detail):
        pytest.skip(f"IDA is unavailable in this environment: {detail.strip()[:400]}")


@functools.lru_cache(maxsize=1)
def _two_runs() -> tuple[Path, Path]:
    """Copy the host PE into a temp dir and extract it twice; returns both outputs.

    Two *separate* subprocesses are used on purpose — that is the only way to show
    the JSON depends on the input alone and not on anything a warm IDA process
    might carry over.
    """
    import tempfile

    work = Path(tempfile.mkdtemp(prefix="icepick-live-extract-"))
    target = work / _HOST_PE.name  # type: ignore[union-attr]
    shutil.copy2(_HOST_PE, target)  # type: ignore[arg-type]

    outputs: list[Path] = []
    for index in (1, 2):
        out = work / f"extract{index}.json"
        result = _run_extract(target, out)
        _skip_if_unavailable(result)
        assert result.returncode == 0, (
            f"run {index} failed with rc={result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        assert out.is_file(), f"run {index} wrote no document at {out}"
        outputs.append(out)
    return outputs[0], outputs[1]


@pytest.fixture(scope="module")
def extraction() -> tuple[bytes, bytes, dict]:
    """The two raw documents plus the parsed first one."""
    first, second = _two_runs()
    raw_a = first.read_bytes()
    raw_b = second.read_bytes()
    return raw_a, raw_b, json.loads(raw_a.decode("utf-8"))


# --------------------------------------------------------------------------
# the criterion itself
# --------------------------------------------------------------------------
def test_two_runs_are_byte_identical(extraction):
    raw_a, raw_b, _ = extraction
    assert raw_a == raw_b, "two extraction runs produced different JSON bytes"


def test_json_is_utf8_lf_terminated_and_canonical(extraction):
    raw_a, _, document = extraction
    assert raw_a.endswith(b"\n")
    assert b"\r\n" not in raw_a
    assert not raw_a.startswith(b"\xef\xbb\xbf")
    # dumps_document uses sort_keys=True/indent=2; re-dumping must reproduce it.
    assert raw_a.decode("utf-8") == extract.dumps_document(document)


def test_document_passes_schema_validation(extraction):
    _, _, document = extraction
    assert schema.validate_extract(document) == []


def test_document_declares_idalib_provenance(extraction):
    _, _, document = extraction
    provenance = document["provenance"]
    assert document["schema_version"] == schema.SCHEMA_VERSION
    assert document["kind"] == "extract"
    assert document["doc_source"] == "ida"
    assert provenance["backend"] == "idalib"
    assert schema.SHA256_RE.match(provenance["idb_sha256"])
    assert isinstance(provenance["auto_analysis"], bool)
    assert provenance["ida_version"]


def test_document_holds_at_least_one_function(extraction):
    _, _, document = extraction
    assert document["funcs"], "a real PE must analyze to at least one function"
    eas = [func["ea"] for func in document["funcs"]]
    assert eas == sorted(eas)
    assert len(eas) == len(set(eas))


def test_canonical_digest_matches_across_the_two_runs(extraction):
    raw_a, raw_b, _ = extraction
    first = json.loads(raw_a.decode("utf-8"))
    second = json.loads(raw_b.decode("utf-8"))
    assert schema.extract_digest(first) == schema.extract_digest(second)


def test_output_leaks_no_host_or_runner_detail(extraction):
    """No run path, temp directory or input file name may appear in the document."""
    raw_a, _, _ = extraction
    text = raw_a.decode("utf-8")
    assert "icepick-live-extract-" not in text
    assert _HOST_PE.name not in text  # type: ignore[union-attr]
    assert str(ROOT) not in text
    assert str(SRC) not in text
    assert "extract1.json" not in text and "extract2.json" not in text


def test_every_function_has_decompile_or_sentinel(extraction):
    """U-IDA3: each func carries decompiler text or a non-ok status sentinel."""
    _, _, document = extraction
    assert document["funcs"]
    for func in document["funcs"]:
        text = (func.get("decompiled") or "").strip()
        status = func.get("decompile_status", "ok")
        assert status in schema.DECOMPILE_STATUSES, (
            f"func {func.get('ea')}: unknown status {status!r}"
        )
        assert text or status != "ok", (
            f"func {func.get('ea')}: neither decompile text nor sentinel"
        )
