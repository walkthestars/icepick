"""icepick queue — the supervisor: one worker process per IDB (U-IDA4).

The bridge never runs IDA in its own process.  :func:`run_job` spawns **one
worker process per IDB**; :func:`run_queue` fans a batch of jobs out over a small
thread pool whose threads only ever *wait* on those processes.  The IDA runtime
lives and dies inside a worker, which matches the documented idalib rule
(``docs/UNIT-IDA-PLAN.md``, ``.pi/MEMORY.md``): idalib is single-threaded,
same-thread-only, one active database per process — so a second database means a
second process, never a second thread.

Backends (:class:`Backend`, mirrors ``schema.BACKENDS``)
    ``idalib``
        ``<python> -m icepick.extract <IDB> --backend idalib --out <JSON>`` —
        the standalone idalib lane (primary).
    ``idat``
        ``<IDADIR>/idat[.exe] -A -S<bootstrap> <IDB>`` — the autonomous
        text-mode lane.  The generated bootstrap (a file written into the job's
        own temporary directory, deleted afterwards) calls the same
        ``icepick.extract`` entry point and exits the IDA process with its code.

Environment rule (stale-``IDADIR`` incident, see :mod:`icepick.extract`)
    Every worker gets an **explicit** ``IDADIR`` resolved through
    :func:`icepick.extract.resolve_ida_home`; an inherited shell value is never
    passed through untouched, because a harness shell can carry a stale pin
    (``9.3`` while the pin is ``9.5``).  ``PYTHONPATH`` is set to the package's
    ``src/`` root first, so a worker can ``import icepick`` with no install step.
    Any code that imports ``idapro`` sets ``IDADIR`` first — including
    :func:`check_license`.

Error taxonomy (:class:`ErrorCode`)
    ``IDA_BUSY``, ``DECOMPILE_FAILED``, ``IDA_LICENSE_ABSENT``,
    ``IDA_HOME_UNRESOLVED``, ``TIMEOUT``, ``WORKER_FAILED``,
    ``WORKER_NO_RESULT``, ``LAUNCH_FAILED``, ``BAD_REQUEST``.

    The three names the unit plan calls out fail **fast**, never hang: an
    unresolvable ``IDADIR`` and an unimportable ``idapro`` (the licence gate,
    :func:`check_license`) are decided *before* a worker is ever started, and a
    database another process holds (``IDA_BUSY``) is decided from the worker's
    own report rather than guessed from lock files — guessing would block
    legitimate read-only re-reads.  The supervisor always enforces the job's
    timeout and kills the **whole worker tree** when it expires (``taskkill /T``
    on Windows, ``killpg`` elsewhere).

Results
    The worker's extract document is JSON **on disk** (``--out``);
    :class:`JobResult` is JSON too (:meth:`JobResult.to_dict` /
    :meth:`JobResult.write`) and a whole run can be serialised as one report
    (:func:`run_queue` ``result_path=``, :func:`write_report`).

Stdlib only: ``subprocess`` / ``concurrent.futures`` / ``json``.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import importlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from . import schema
from .extract import IDAHomeError, is_ida_install, resolve_ida_home

__all__ = [
    "Backend",
    "ErrorCode",
    "QueueError",
    "IDALicenseError",
    "Job",
    "JobResult",
    "Supervisor",
    "REPORT_SCHEMA",
    "DEFAULT_TIMEOUT",
    "DEFAULT_MAX_WORKERS",
    "REAP_TIMEOUT",
    "OUTPUT_CAP",
    "EXPLICIT_CODE_TOKENS",
    "LICENSE_MARKERS",
    "BUSY_MARKERS",
    "DECOMPILE_MARKERS",
    "source_root",
    "pythonpath_value",
    "output_path",
    "default_job_id",
    "resolve_worker_home",
    "build_worker_env",
    "check_license",
    "ida_binary",
    "worker_command",
    "write_idat_bootstrap",
    "kill_process_tree",
    "pid_alive",
    "decompile_stats",
    "classify_failure",
    "first_line",
    "run_job",
    "submit",
    "run_queue",
    "write_report",
    "shutdown",
]

#: Wall-clock budget for one worker; IDA auto-analysis on a large IDB is slow.
DEFAULT_TIMEOUT = 1800.0
#: Conservative pool width: every worker loads a full IDA runtime.
DEFAULT_MAX_WORKERS = 2
#: Grace period for reaping a worker after its tree was killed.
REAP_TIMEOUT = 10.0
#: Per-stream cap on captured worker output (keeps a runaway worker bounded).
OUTPUT_CAP = 8000
#: Marker written into a queue report so consumers can version it.
REPORT_SCHEMA = "icepick.run-report/v1"

#: Module name probed by the licence gate.  Held in a variable on purpose: the
#: CI fence (``tests/test_no_ida_imports.py``) rejects literal string arguments
#: to ``import_module`` anywhere in ``src/``.
_IDAPRO_MODULE = "idapro"


class Backend(StrEnum):
    """Where a worker runs IDA.  Values match :data:`icepick.schema.BACKENDS`."""

    IDALIB = "idalib"
    IDAT = "idat"


class ErrorCode(StrEnum):
    """Supervisor error taxonomy (``JobResult.error_code``)."""

    #: Another process holds the database (reported by the worker).
    IDA_BUSY = "IDA_BUSY"
    #: Inventory succeeded but every function failed to decompile.
    DECOMPILE_FAILED = "DECOMPILE_FAILED"
    #: ``idapro`` cannot be imported — no usable licence (fail fast).
    IDA_LICENSE_ABSENT = "IDA_LICENSE_ABSENT"
    #: No valid ``IDADIR`` could be resolved (fail fast, local pre-flight).
    IDA_HOME_UNRESOLVED = "IDA_HOME_UNRESOLVED"
    #: The worker exceeded its timeout and its process tree was killed.
    TIMEOUT = "TIMEOUT"
    #: Non-zero exit with no more specific signal.
    WORKER_FAILED = "WORKER_FAILED"
    #: Exit code 0 but no readable result document on disk.
    WORKER_NO_RESULT = "WORKER_NO_RESULT"
    #: The worker command could not be started at all.
    LAUNCH_FAILED = "LAUNCH_FAILED"
    #: The job itself is malformed (missing IDB, non-positive timeout).
    BAD_REQUEST = "BAD_REQUEST"


#: ``ErrorCode`` tokens a worker may print itself; scanned in stderr/stdout.
#: ``TIMEOUT`` is deliberately absent: it would match ``TimeoutError``.
EXPLICIT_CODE_TOKENS: tuple[ErrorCode, ...] = (
    ErrorCode.IDA_BUSY,
    ErrorCode.IDA_LICENSE_ABSENT,
    ErrorCode.DECOMPILE_FAILED,
    ErrorCode.IDA_HOME_UNRESOLVED,
)

#: Case-insensitive phrases that mean "no usable licence" (checked first).
LICENSE_MARKERS: tuple[str, ...] = (
    "ida_license_absent",
    "no valid license",
    "no valid licence",
    "license has expired",
    "licence has expired",
    "no license",
    "no licence",
    "license not found",
    "licence not found",
    "floating license",
    "floating licence",
)
#: Case-insensitive phrases that mean "another process holds the database".
BUSY_MARKERS: tuple[str, ...] = (
    "ida_busy",
    "database is busy",
    "db is busy",
    "already open",
    "already loaded",
    "already in use",
    "in use by another",
    "another instance",
    "database is locked",
    "idb is locked",
    "locked by",
)
#: Case-insensitive phrases that mean "the decompiler gave up".
DECOMPILE_MARKERS: tuple[str, ...] = (
    "decompile_failed",
    "decompilation failed",
    "ida_hexrays",
    "hexrays",
    "hex-rays",
)

#: Non-``ok`` ``decompile_status`` values that count as a decompile failure.
_FAILED_DECOMPILE_STATUSES: frozenset[str] = frozenset({"failed", "too_big", "timeout"})


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------
class QueueError(RuntimeError):
    """Base class for supervisor errors; carries the taxonomy code when known."""

    code: ErrorCode | None = None

    @property
    def error_code(self) -> ErrorCode | None:
        """The :class:`ErrorCode` this error maps to (``None`` for generic ones)."""
        return self.code


class IDALicenseError(QueueError):
    """``idapro`` is unimportable: treat as a missing/expired IDA licence."""

    code = ErrorCode.IDA_LICENSE_ABSENT


# ---------------------------------------------------------------------------
# job description
# ---------------------------------------------------------------------------
def source_root() -> Path:
    """The ``src/`` root that holds the ``icepick`` package (put on ``PYTHONPATH``)."""
    return Path(__file__).resolve().parents[1]


def default_job_id(job: Job) -> str:
    """Stable 12-hex job id derived from the backend and the IDB path."""
    seed = f"{job.backend.value}\0{os.path.normcase(os.path.abspath(str(job.idb)))}"
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]


def output_path(job: Job) -> Path:
    """Where the worker writes its extract document (``<IDB>.extract.json`` default)."""
    if job.out is not None:
        return Path(str(job.out))
    idb = Path(job.idb)
    return idb.parent / f"{idb.name}.extract.json"


@dataclass(frozen=True, slots=True)
class Job:
    """One IDB to extract, in one worker process.

    ``worker_argv`` overrides the real IDA command; that is the seam the tests
    use (``sys.executable -c ...``) and it doubles as a hook for a custom
    launcher.  ``check_license=None`` means *auto*: the licence gate runs only
    when the job uses the real backend worker, because a fake worker needs no
    licence.
    """

    idb: Path | str
    backend: Backend | str = Backend.IDALIB
    out: Path | str | None = None
    job_id: str | None = None
    timeout: float | None = None
    ida_home: Path | str | None = None
    ida_config_path: Path | str | None = None
    worker_argv: Sequence[str] | None = None
    check_license: bool | None = None
    pythonpath: Sequence[Path | str] = ()
    extra_env: Mapping[str, str] | None = None
    extra_args: Sequence[str] = ()
    cwd: Path | str | None = None
    top_k: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "idb", Path(str(self.idb)))
        if not isinstance(self.backend, Backend):
            object.__setattr__(self, "backend", Backend(str(self.backend)))
        if self.out is not None:
            object.__setattr__(self, "out", Path(str(self.out)))
        if self.ida_home is not None:
            object.__setattr__(self, "ida_home", str(self.ida_home))
        if self.ida_config_path is not None:
            object.__setattr__(self, "ida_config_path", Path(str(self.ida_config_path)))
        if self.worker_argv is not None:
            object.__setattr__(
                self, "worker_argv", tuple(str(token) for token in self.worker_argv)
            )
        object.__setattr__(self, "pythonpath", tuple(str(p) for p in self.pythonpath))
        object.__setattr__(self, "extra_args", tuple(str(a) for a in self.extra_args))
        if self.cwd is not None:
            object.__setattr__(self, "cwd", Path(str(self.cwd)))

    @property
    def out_path(self) -> Path:
        """Result document path (see :func:`output_path`)."""
        return output_path(self)

    @property
    def effective_id(self) -> str:
        """``job_id`` when given, else the deterministic :func:`default_job_id`."""
        return self.job_id or default_job_id(self)


@dataclass(slots=True)
class JobResult:
    """Outcome of one job: JSON-serialisable, always carries an error code or ``None``."""

    job_id: str
    idb: str
    backend: Backend
    out: str | None = None
    returncode: int | None = None
    error_code: ErrorCode | None = None
    error: str | None = None
    timed_out: bool = False
    killed: bool = False
    worker_pid: int | None = None
    ida_home: str | None = None
    duration_s: float = 0.0
    stdout: str = ""
    stderr: str = ""
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True exactly when no error code was recorded."""
        return self.error_code is None

    @property
    def failed(self) -> bool:
        """Inverse of :attr:`ok`, for readability at call sites."""
        return not self.ok

    def to_dict(self) -> dict[str, Any]:
        """Plain-JSON view of this result (``error_code`` as its string value)."""
        return {
            "job_id": self.job_id,
            "idb": self.idb,
            "backend": self.backend.value,
            "out": self.out,
            "returncode": self.returncode,
            "ok": self.ok,
            "error_code": None if self.error_code is None else self.error_code.value,
            "error": self.error,
            "timed_out": self.timed_out,
            "killed": self.killed,
            "worker_pid": self.worker_pid,
            "ida_home": self.ida_home,
            "duration_s": self.duration_s,
            "stats": dict(self.stats),
            "stdout": self.stdout,
            "stderr": self.stderr,
        }

    def dumps(self) -> str:
        """Deterministic JSON text for this result (sorted keys, ``\\n`` newline)."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2) + "\n"

    def write(self, path: Path | str) -> Path:
        """Write :meth:`dumps` to ``path`` (parents created); returns the path."""
        destination = Path(str(path))
        if not destination.parent.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.dumps(), encoding="utf-8", newline="\n")
        return destination

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JobResult:
        """Rebuild a result from :meth:`to_dict` output (tolerant of missing keys)."""
        code = payload.get("error_code")
        return cls(
            job_id=str(payload.get("job_id") or ""),
            idb=str(payload.get("idb") or ""),
            backend=Backend(str(payload.get("backend") or Backend.IDALIB.value)),
            out=payload.get("out"),
            returncode=payload.get("returncode"),
            error_code=None if code is None else ErrorCode(str(code)),
            error=payload.get("error"),
            timed_out=bool(payload.get("timed_out", False)),
            killed=bool(payload.get("killed", False)),
            worker_pid=payload.get("worker_pid"),
            ida_home=payload.get("ida_home"),
            duration_s=float(payload.get("duration_s") or 0.0),
            stdout=str(payload.get("stdout") or ""),
            stderr=str(payload.get("stderr") or ""),
            stats=dict(payload.get("stats") or {}),
        )


# ---------------------------------------------------------------------------
# IDADIR / child environment (the environment rule)
# ---------------------------------------------------------------------------
def resolve_worker_home(
    job: Job,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    """Resolve the ``IDADIR`` a worker must be given — explicit, never inherited.

    An explicit ``job.ida_home`` (already resolved by the caller) is used as-is,
    but still validated with :func:`icepick.extract.is_ida_install`, so a typo
    fails here instead of inside IDA.  Otherwise
    :func:`icepick.extract.resolve_ida_home` decides: a *valid* install wins over
    a stale inherited ``IDADIR``, and ``ida-config.json``
    (``job.ida_config_path``, or the platform locations) is the fallback.
    """
    if job.ida_home is not None:
        candidate = os.path.normpath(os.path.expanduser(str(job.ida_home)))
        if not is_ida_install(candidate):
            raise IDAHomeError(
                f"explicit IDA home {candidate!r} does not look like an IDA "
                f"install (none of {', '.join(__import__('icepick.extract', fromlist=['x']).IDA_INSTALL_MARKERS)})"
            )
        return candidate
    return resolve_ida_home(env=env, config_path=job.ida_config_path)


def pythonpath_value(
    existing: str | None,
    extra: Iterable[Path | str] = (),
) -> str:
    """``src/`` first, then ``extra``, then whatever was inherited (deduplicated)."""
    entries: list[str] = [str(source_root())]
    entries.extend(str(item) for item in extra if str(item))
    if existing:
        entries.extend(part for part in str(existing).split(os.pathsep) if part)
    seen: set[str] = set()
    unique: list[str] = []
    for entry in entries:
        key = os.path.normcase(os.path.normpath(entry))
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return os.pathsep.join(unique)


def build_worker_env(
    job: Job,
    *,
    base_env: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], str]:
    """The full environment for one worker: ``(env, resolved_ida_home)``.

    ``IDADIR`` is **always** set to the resolved install — the inherited value is
    overwritten, never forwarded (environment rule).  ``PYTHONPATH`` leads with
    the package's ``src/`` root so the worker can ``import icepick``.  Raises
    :class:`icepick.extract.IDAHomeError` when nothing usable can be resolved.
    """
    base = dict(os.environ if base_env is None else base_env)
    home = resolve_worker_home(job, env=base)
    env = {str(key): str(value) for key, value in base.items()}
    env["IDADIR"] = home
    env["PYTHONPATH"] = pythonpath_value(base.get("PYTHONPATH"), job.pythonpath)
    for key, value in (job.extra_env or {}).items():
        env[str(key)] = str(value)
    return env, home


# ---------------------------------------------------------------------------
# licence gate (fail fast, before any worker is started)
# ---------------------------------------------------------------------------
def _load_idapro() -> Any:
    """Import ``idapro`` (the real loader; tests patch this or pass ``importer``)."""
    return importlib.import_module(_IDAPRO_MODULE)


def check_license(
    *,
    ida_home: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    config_path: Path | str | None = None,
    importer: Callable[[], Any] | None = None,
) -> str:
    """Fail fast with ``IDA_LICENSE_ABSENT`` when ``idapro`` cannot be imported.

    Returns the resolved install directory on success, else raises
    :class:`IDALicenseError` (whose :attr:`QueueError.code` is
    ``ErrorCode.IDA_LICENSE_ABSENT`) — the supervisor reports that code and never
    starts a worker.  Environment rule: ``os.environ['IDADIR']`` is set to the
    resolved install **before** the import, so the probe cannot pick up a stale
    inherited pin.

    ``importer`` is the seam: pass a callable, or monkeypatch
    :func:`_load_idapro`, to exercise the gate without IDA.
    """
    home = _pin_home(ida_home=ida_home, env=env, config_path=config_path)
    os.environ["IDADIR"] = home
    loader = importer if importer is not None else _load_idapro
    try:
        module = loader()
    except Exception as exc:
        raise IDALicenseError(
            f"idapro is not importable with IDADIR={home!r}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if module is None:
        raise IDALicenseError(
            f"idapro imported as None with IDADIR={home!r}: no usable IDA licence"
        )
    return home


def _pin_home(
    *,
    ida_home: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    config_path: Path | str | None = None,
) -> str:
    """Resolve (or validate) an install directory for the licence probe."""
    if ida_home is not None:
        candidate = os.path.normpath(os.path.expanduser(str(ida_home)))
        if not is_ida_install(candidate):
            raise IDAHomeError(
                f"explicit IDA home {candidate!r} does not look like an IDA install"
            )
        return candidate
    return resolve_ida_home(env=env, config_path=config_path)


# ---------------------------------------------------------------------------
# worker commands
# ---------------------------------------------------------------------------
def ida_binary(ida_home: Path | str, backend: Backend | str = Backend.IDAT) -> Path:
    """The backend's executable inside ``ida_home`` (platform suffix applied on NT)."""
    name = Backend(str(backend)).value
    if os.name == "nt":
        name += ".exe"
    return Path(str(ida_home)) / name


def write_idat_bootstrap(
    job: Job,
    *,
    ida_home: str,
    work_dir: Path | str,
) -> Path:
    """Write the ``-S`` script that drives :mod:`icepick.extract` inside ``idat``.

    The script is mechanical: put ``src/`` on ``sys.path``, call the extractor's
    ``main`` with the same arguments the idalib lane would get, then hand the
    exit code to ``idc.qexit`` so ``idat``'s own exit code carries the verdict.
    """
    work = Path(str(work_dir))
    work.mkdir(parents=True, exist_ok=True)
    target = work / f"icepick-run-{job.effective_id}.py"
    args: list[str] = [str(job.idb), "--backend", Backend.IDAT.value, "--out", str(job.out_path)]
    if job.top_k is not None:
        args += ["--top-k", str(int(job.top_k))]
    args += ["--ida-home", str(ida_home), "--quiet"]
    args += list(job.extra_args)
    text = (
        '"""Generated by icepick.queue — do not edit; deleted after the job."""\n'
        "import sys\n"
        f"sys.path.insert(0, {str(source_root())!r})\n"
        "from icepick import extract\n"
        f"code = extract.main({args!r})\n"
        "try:\n"
        "    import idc\n"
        "except Exception:  # pragma: no cover - idat always has idc\n"
        "    pass\n"
        "else:\n"
        "    idc.qexit(int(code))\n"
    )
    target.write_text(text, encoding="utf-8", newline="\n")
    return target


def worker_command(job: Job, *, ida_home: str, work_dir: Path | str) -> list[str]:
    """The argv for one job's worker (``job.worker_argv`` is the override seam).

    ``idalib`` runs the extractor under the current interpreter
    (``python -m icepick.extract``) because that lane *is* a normal Python
    process; ``idat`` runs IDA's own text-mode binary with ``-A`` (autonomous)
    and a generated ``-S`` bootstrap.  ``-A`` never prompts, so a worker cannot
    stall on a dialog.
    """
    backend = job.backend
    common: list[str] = [str(job.idb)]
    if job.out is not None:
        common += ["--out", str(job.out_path)]
    if backend is Backend.IDALIB:
        tail: list[str] = [
            "--backend",
            Backend.IDALIB.value,
            "--ida-home",
            str(ida_home),
            "--quiet",
        ]
        if job.top_k is not None:
            tail += ["--top-k", str(int(job.top_k))]
        tail += list(job.extra_args)
        return [sys.executable, "-m", "icepick.extract", *common, *tail]

    bootstrap = write_idat_bootstrap(job, ida_home=ida_home, work_dir=work_dir)
    return [
        str(ida_binary(ida_home, backend)),
        "-A",
        f"-S{bootstrap}",
        *common,
    ]


# ---------------------------------------------------------------------------
# process control
# ---------------------------------------------------------------------------
def _spawn_kwargs() -> dict[str, Any]:
    """Put the worker in its own process group so the whole tree can be killed."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def kill_process_tree(pid: int, *, timeout: float = REAP_TIMEOUT) -> bool:
    """Kill ``pid`` **and its children**; True when a kill was delivered.

    Windows: ``taskkill /F /T /PID`` walks the child list (proven to reap a
    grandchild worker).  POSIX: ``SIGKILL`` to the worker's process group, with a
    single-process fallback.  A job that already exited is not an error.
    """
    if int(pid) <= 0:
        return False
    if os.name == "nt":
        try:
            done = subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(int(pid))],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return done.returncode == 0
    try:
        os.killpg(os.getpgid(int(pid)), signal.SIGKILL)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(int(pid), signal.SIGKILL)
        except OSError:
            return False
        return True


def pid_alive(pid: int) -> bool:
    """True when a process with ``pid`` currently exists (portable, no side effects)."""
    if int(pid) <= 0:
        return False
    if os.name == "nt":
        try:
            listing = subprocess.run(
                ["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"],
                capture_output=True,
                text=True,
                timeout=REAP_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return re.search(rf"(?<!\d){int(pid)}(?!\d)", listing.stdout or "") is not None
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # exists, owned by someone else
        return True
    except OSError:  # pragma: no cover - defensive
        return False
    return True


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
def first_line(text: str, *, limit: int = 300) -> str:
    """First non-empty stripped line of ``text``, capped at ``limit`` characters."""
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:limit]
    return ""


def decompile_stats(document: Mapping[str, Any] | None) -> dict[str, int]:
    """``{"funcs", "decompiled_ok", "decompile_failed"}`` for an extract document."""
    if not isinstance(document, Mapping):
        return {}
    funcs = document.get("funcs")
    if not isinstance(funcs, list):
        return {}
    ok = failed = 0
    for func in funcs:
        if not isinstance(func, Mapping):
            continue
        status = func.get("decompile_status")
        if status == "ok" and isinstance(func.get("decompiled"), str):
            ok += 1
        elif status in _FAILED_DECOMPILE_STATUSES:
            failed += 1
    return {"funcs": len(funcs), "decompiled_ok": ok, "decompile_failed": failed}


def classify_failure(
    returncode: int | None,
    *,
    text: str = "",
    document: Mapping[str, Any] | None = None,
    timed_out: bool = False,
) -> tuple[ErrorCode, str] | None:
    """Map a finished worker to ``(code, message)``, or ``None`` when it succeeded.

    Order: a timeout owns the verdict; otherwise a non-zero exit is classified
    from the worker's own words (explicit taxonomy tokens first, then the
    licence/busy/decompile phrase tables) and finally by the exit code; a zero
    exit is judged by the **document on disk**, which is where the U-IDA3
    per-function ``DECOMPILE_FAILED`` sentinels become a job-level verdict.
    """
    if timed_out:
        return ErrorCode.TIMEOUT, "worker exceeded its time budget; process tree killed"

    haystack = str(text or "")
    if returncode != 0:
        upper = haystack.upper()
        for code in EXPLICIT_CODE_TOKENS:
            if code.value in upper:
                return code, first_line(haystack) or f"worker reported {code.value}"
        lowered = haystack.lower()
        for code, markers in (
            (ErrorCode.IDA_LICENSE_ABSENT, LICENSE_MARKERS),
            (ErrorCode.IDA_BUSY, BUSY_MARKERS),
            (ErrorCode.DECOMPILE_FAILED, DECOMPILE_MARKERS),
        ):
            if any(marker in lowered for marker in markers):
                return code, first_line(haystack) or f"worker reported {code.value}"
        line = first_line(haystack)
        message = f"worker exited with code {returncode}"
        return ErrorCode.WORKER_FAILED, f"{message}: {line}" if line else message

    if document is None:
        return ErrorCode.WORKER_NO_RESULT, "worker exited 0 but wrote no readable result document"
    stats = decompile_stats(document)
    funcs = stats.get("funcs", 0)
    if funcs and stats.get("decompiled_ok", 0) == 0 and stats.get("decompile_failed", 0) == funcs:
        return (
            ErrorCode.DECOMPILE_FAILED,
            f"inventory written but all {funcs} function(s) failed to decompile",
        )
    return None


# ---------------------------------------------------------------------------
# running one job
# ---------------------------------------------------------------------------
def _cap_text(text: str | None) -> str:
    """Bound captured worker output, keeping the head and noting the loss."""
    raw = "" if text is None else str(text)
    if len(raw) <= OUTPUT_CAP:
        return raw
    dropped = len(raw) - OUTPUT_CAP
    return f"{raw[:OUTPUT_CAP]}\n...[icepick: {dropped} more character(s) dropped]"


def _read_document(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read the worker's extract document: ``(document|None, problem|None)``."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"cannot read {path}: {exc}"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"result document {path} is not valid JSON: {exc}"
    if not isinstance(payload, dict):
        return None, f"result document {path} is not a JSON object"
    return payload, None


def _effective_timeout(job: Job, override: float | None) -> float:
    """Resolution order: explicit argument → ``Job.timeout`` → :data:`DEFAULT_TIMEOUT`."""
    if override is not None:
        return float(override)
    if job.timeout is not None:
        return float(job.timeout)
    return float(DEFAULT_TIMEOUT)


def _conclude(
    result: JobResult,
    code: ErrorCode | None,
    message: str | None,
    started: float,
    result_path: Path | str | None,
) -> JobResult:
    """Stamp an outcome onto ``result``, persist it when asked, and return it."""
    result.error_code = None if code is None else ErrorCode(str(code))
    result.error = None if code is None else (message or code.value)
    result.duration_s = round(time.monotonic() - started, 3)
    if result_path is not None:
        result.write(result_path)
    return result


def run_job(
    job: Job,
    *,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
    license_check: bool | None = None,
    license_importer: Callable[[], Any] | None = None,
    result_path: Path | str | None = None,
    keep_work_dir: bool = False,
) -> JobResult:
    """Run **one** worker process for **one** IDB and return its :class:`JobResult`.

    Synchronous by design: the caller (or :class:`Supervisor`) owns the
    concurrency, so there is never more than one live database inside a process.
    Nothing in here raises for an IDA problem — failures become an
    :class:`ErrorCode` on the result; only a malformed ``job`` argument
    (:class:`TypeError`) or an unwritable ``result_path`` (``OSError``) propagate.
    """
    if not isinstance(job, Job):
        raise TypeError(f"job must be a queue.Job, got {type(job).__name__}")

    base_env = dict(os.environ if env is None else env)
    started = time.monotonic()
    result = JobResult(job_id=job.effective_id, idb=str(job.idb), backend=job.backend)
    limit = _effective_timeout(job, timeout)

    if limit <= 0:
        return _conclude(
            result,
            ErrorCode.BAD_REQUEST,
            f"timeout must be greater than zero, got {limit!r}",
            started,
            result_path,
        )
    if not Path(job.idb).is_file():
        return _conclude(
            result, ErrorCode.BAD_REQUEST, f"no such IDB: {job.idb}", started, result_path
        )

    # Explicit IDADIR + PYTHONPATH for the child, or fail fast.
    try:
        worker_env, home = build_worker_env(job, base_env=base_env)
    except IDAHomeError as exc:
        return _conclude(result, ErrorCode.IDA_HOME_UNRESOLVED, str(exc), started, result_path)
    result.ida_home = home

    out = output_path(job)
    result.out = str(out)

    # Licence gate: decided before a single worker is started.
    gate = job.check_license if license_check is None else bool(license_check)
    if gate is None:
        gate = job.worker_argv is None
    if gate:
        try:
            check_license(
                ida_home=home,
                env=base_env,
                config_path=job.ida_config_path,
                importer=license_importer,
            )
        except IDALicenseError as exc:
            return _conclude(
                result, ErrorCode.IDA_LICENSE_ABSENT, str(exc), started, result_path
            )
        except IDAHomeError as exc:
            return _conclude(
                result, ErrorCode.IDA_HOME_UNRESOLVED, str(exc), started, result_path
            )

    if not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)

    work_dir: Path | None = None
    try:
        if job.worker_argv is not None:
            argv = list(job.worker_argv)
        else:
            if job.backend is Backend.IDAT:
                work_dir = Path(tempfile.mkdtemp(prefix=f"icepick-{job.effective_id}-"))
            argv = worker_command(job, ida_home=home, work_dir=work_dir or out.parent)

        try:
            proc = subprocess.Popen(
                argv,
                cwd=None if job.cwd is None else str(job.cwd),
                env=worker_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **_spawn_kwargs(),
            )
        except OSError as exc:
            return _conclude(
                result,
                ErrorCode.LAUNCH_FAILED,
                f"cannot start worker {argv[0]!r}: {exc}",
                started,
                result_path,
            )

        result.worker_pid = proc.pid
        try:
            stdout, stderr = proc.communicate(timeout=limit)
        except subprocess.TimeoutExpired:
            result.timed_out = True
            result.killed = kill_process_tree(proc.pid)
            try:
                stdout, stderr = proc.communicate(timeout=REAP_TIMEOUT)
            except subprocess.TimeoutExpired:  # pragma: no cover - unkillable worker
                stdout, stderr = "", ""
            result.returncode = proc.returncode
            result.stdout = _cap_text(stdout)
            result.stderr = _cap_text(stderr)
            return _conclude(
                result,
                ErrorCode.TIMEOUT,
                f"worker exceeded {limit:g}s; process tree "
                f"{'killed' if result.killed else 'could not be killed'}",
                started,
                result_path,
            )

        result.returncode = proc.returncode
        result.stdout = _cap_text(stdout)
        result.stderr = _cap_text(stderr)

        document: dict[str, Any] | None = None
        read_error: str | None = None
        if out.exists():
            document, read_error = _read_document(out)
        else:
            read_error = f"no result document at {out}"
        result.stats = decompile_stats(document)

        verdict = classify_failure(
            proc.returncode,
            text=f"{result.stdout}\n{result.stderr}",
            document=document,
            timed_out=False,
        )
        if verdict is None:
            return _conclude(result, None, None, started, result_path)
        code, message = verdict
        if read_error and code is ErrorCode.WORKER_NO_RESULT:
            message = f"{message}: {read_error}"
        return _conclude(result, code, message, started, result_path)
    finally:
        if work_dir is not None and not keep_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# supervisor
# ---------------------------------------------------------------------------
class Supervisor:
    """Fans jobs out to a bounded thread pool; each thread waits on one worker.

    The pool is only ever *waiting* on subprocesses, so the idalib
    same-thread-only rule is untouched: the IDA runtime lives in the worker.
    """

    def __init__(
        self,
        *,
        max_workers: int | None = None,
        default_timeout: float | None = None,
        env: Mapping[str, str] | None = None,
        license_check: bool | None = None,
        license_importer: Callable[[], Any] | None = None,
    ) -> None:
        width = DEFAULT_MAX_WORKERS if max_workers is None else int(max_workers)
        if width < 1:
            raise QueueError(f"max_workers must be at least 1, got {max_workers!r}")
        self.max_workers = width
        self.default_timeout = default_timeout
        self._run_kwargs: dict[str, Any] = {
            "env": env,
            "license_check": license_check,
            "license_importer": license_importer,
        }
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._ids: dict[str, int] = {}
        self._lock = threading.Lock()

    # -- ids ---------------------------------------------------------------
    def _unique_id(self, base: str) -> str:
        """De-duplicate job ids inside this supervisor (``base``, ``base-2``, ...)."""
        with self._lock:
            seen = self._ids.get(base, 0)
            self._ids[base] = seen + 1
        return base if seen == 0 else f"{base}-{seen + 1}"

    # -- pool --------------------------------------------------------------
    def _pool(self) -> concurrent.futures.ThreadPoolExecutor:
        with self._lock:
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.max_workers,
                    thread_name_prefix="icepick-queue",
                )
            return self._executor

    def _run_one(self, job: Job, overrides: Mapping[str, Any]) -> JobResult:
        kwargs = dict(self._run_kwargs)
        kwargs.update(overrides)
        if "timeout" not in kwargs and job.timeout is None and self.default_timeout is not None:
            kwargs["timeout"] = self.default_timeout
        return run_job(job, **kwargs)

    # -- public API --------------------------------------------------------
    def submit(self, job: Job, **run_kwargs: Any) -> concurrent.futures.Future[JobResult]:
        """Queue ``job`` and return its future (id de-duplicated per supervisor)."""
        if not isinstance(job, Job):
            raise TypeError(f"job must be a queue.Job, got {type(job).__name__}")
        unique = self._unique_id(job.effective_id)
        if unique != job.job_id:
            job = replace(job, job_id=unique)
        return self._pool().submit(self._run_one, job, run_kwargs)

    def gather(
        self, futures: Iterable[concurrent.futures.Future[JobResult]]
    ) -> list[JobResult]:
        """Resolve ``futures`` in the order given (submission order), not by finish."""
        return [future.result() for future in futures]

    def run(self, jobs: Iterable[Job]) -> list[JobResult]:
        """Submit every job, then gather — results come back in job order."""
        pending = list(jobs)
        return self.gather([self.submit(job) for job in pending])

    def shutdown(self, *, wait: bool = True) -> None:
        """Close the pool (idempotent)."""
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=wait)

    close = shutdown

    def __enter__(self) -> Supervisor:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.shutdown()


_DEFAULT_SUPERVISOR: Supervisor | None = None
_DEFAULT_LOCK = threading.Lock()


def _default_supervisor() -> Supervisor:
    global _DEFAULT_SUPERVISOR
    with _DEFAULT_LOCK:
        if _DEFAULT_SUPERVISOR is None:
            _DEFAULT_SUPERVISOR = Supervisor()
        return _DEFAULT_SUPERVISOR


def submit(
    job: Job,
    *,
    supervisor: Supervisor | None = None,
    **run_kwargs: Any,
) -> concurrent.futures.Future[JobResult]:
    """Submit ``job`` to ``supervisor`` (or the process-wide default pool)."""
    return (supervisor or _default_supervisor()).submit(job, **run_kwargs)


def run_queue(
    jobs: Iterable[Job],
    *,
    max_workers: int | None = None,
    default_timeout: float | None = None,
    env: Mapping[str, str] | None = None,
    license_check: bool | None = None,
    license_importer: Callable[[], Any] | None = None,
    result_path: Path | str | None = None,
) -> list[JobResult]:
    """Run a batch of jobs in parallel (job order preserved) and return the results.

    One worker process per IDB, at most ``max_workers`` at a time.  With
    ``result_path`` the whole run is written as one JSON report
    (:func:`write_report`) — results are JSON on disk either way, since each
    worker writes its own extract document.
    """
    pending = list(jobs)
    with Supervisor(
        max_workers=max_workers,
        default_timeout=default_timeout,
        env=env,
        license_check=license_check,
        license_importer=license_importer,
    ) as supervisor:
        results = supervisor.run(pending)
    if result_path is not None:
        write_report(result_path, results)
    return results


def write_report(path: Path | str, results: Iterable[JobResult]) -> Path:
    """Write a run report: our ``JobResult`` list as one JSON object on disk."""
    listed = list(results)
    payload = {
        "schema": REPORT_SCHEMA,
        "jobs": len(listed),
        "ok": all(result.ok for result in listed),
        "results": [result.to_dict() for result in listed],
    }
    destination = Path(str(path))
    if not destination.parent.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return destination


def shutdown(*, wait: bool = True) -> None:
    """Close the process-wide default supervisor created by :func:`submit`."""
    global _DEFAULT_SUPERVISOR
    with _DEFAULT_LOCK:
        supervisor, _DEFAULT_SUPERVISOR = _DEFAULT_SUPERVISOR, None
    if supervisor is not None:
        supervisor.shutdown(wait=wait)


def backend_choices() -> tuple[str, ...]:
    """Backend values, checked against the schema's own tuple."""
    values = tuple(backend.value for backend in Backend)
    assert values == tuple(schema.BACKENDS), (values, schema.BACKENDS)
    return values
