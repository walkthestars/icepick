"""Supervisor tests — **fake workers only**, no IDA anywhere in sight.

Every worker in this file is a ``sys.executable -c '...'`` snippet: a normal
Python child that writes the extract document the supervisor expects.  That is
the seam :class:`icepick.queue.Job` documents (``worker_argv``), and it means
this module runs green on a machine without IDA, idalib or a licence.

Covered contract (``docs/UNIT-IDA-PLAN.md``, U-IDA4):

* :func:`icepick.queue.run_job` — a successful worker's document is passed
  through (``out`` / ``stats`` / ``stdout`` / ``JobResult.ok``);
* the timeout owns the verdict: a hung worker is **killed** and reported with
  :data:`icepick.queue.ErrorCode.TIMEOUT`, never waited out;
* the environment rule: the child gets an **explicit** ``IDADIR`` (an inherited,
  stale value is overwritten, not forwarded) and ``src/`` first on
  ``PYTHONPATH`` — asserted from inside the child, which echoes its own env;
* the licence gate fails **fast**: with ``idapro`` unimportable (monkeypatched
  ``sys.modules``) :func:`icepick.queue.check_license` raises
  :class:`icepick.queue.IDALicenseError`, and :func:`run_job` reports
  ``IDA_LICENSE_ABSENT`` *before* a worker is started;
* :func:`icepick.queue.ida_binary` — one backend, one executable name;
* the error taxonomy: :func:`icepick.queue.classify_failure` spot-checks plus
  whole-job codes (``BAD_REQUEST``, ``LAUNCH_FAILED``, ``WORKER_NO_RESULT``,
  ``WORKER_FAILED``, ``IDA_HOME_UNRESOLVED``, ``IDA_LICENSE_ABSENT``,
  ``TIMEOUT``);
* :class:`icepick.queue.Supervisor.submit` — two jobs, two isolated worker
  processes, results back in submission order.

The process environment is neutralised per test (``isolated_env``) so a real
IDA install on the developer machine cannot make a test pass or fail by
accident.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, cast

import pytest

from icepick import queue as queue_module
from icepick.queue import (
    Backend,
    ErrorCode,
    IDALicenseError,
    Job,
    JobResult,
    Supervisor,
    build_worker_env,
    check_license,
    classify_failure,
    first_line,
    ida_binary,
    output_path,
    run_job,
    run_queue,
    source_root,
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

#: Marker file that makes a temporary directory look like an IDA install.
MARKER = "idalib.dll"

#: Environment variables that can steer IDA home resolution.
_IDA_ENV_VARS = (
    "IDADIR",
    "IDA_CONFIG_PATH",
    "IDACONFIG",
    "XDG_CONFIG_HOME",
    "APPDATA",
    "HOME",
    "USERPROFILE",
)


# ---------------------------------------------------------------------------
# fixtures and fake-worker helpers
# ---------------------------------------------------------------------------
@pytest.fixture()
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Strip every IDA hint from the environment (only what a test passes counts)."""
    for name in _IDA_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    empty = tmp_path / "isolated-env"
    empty.mkdir(parents=True, exist_ok=True)
    for name in ("APPDATA", "XDG_CONFIG_HOME", "HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(empty))
    return empty


@pytest.fixture()
def fake_install(tmp_path: Path) -> Path:
    """A fake IDA install: a directory holding one :data:`MARKER` file."""
    home = tmp_path / "IDA 9.5"
    home.mkdir(parents=True, exist_ok=True)
    (home / MARKER).write_text("", encoding="utf-8")
    return home


def _worker(body: str) -> list[str]:
    """Turn an inline snippet into a fake worker command (no shell, no IDA)."""
    return [sys.executable, "-c", textwrap.dedent(body).strip()]


def _write_idb(path: Path, data: bytes = b"MZ-fake-idb") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _norm(path: object) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


_WRITE_DOCUMENT = """
    import json
    import os

    document = json.loads(os.environ["ICEPICK_DOCUMENT"])
    with open(os.environ["ICEPICK_RESULT_OUT"], "w", encoding="utf-8") as handle:
        json.dump(document, handle)
    print("fake-worker ok")
"""

_WRITE_ENV_ECHO = """
    import json
    import os
    import sys

    payload = {
        "IDADIR": os.environ.get("IDADIR"),
        "PYTHONPATH": os.environ.get("PYTHONPATH"),
        "ICEPICK_CHILD_MARKER": os.environ.get("ICEPICK_CHILD_MARKER"),
        "STALE_IDADIR": os.environ.get("STALE_IDADIR"),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "argv": list(sys.argv),
    }
    with open(os.environ["ICEPICK_ECHO_OUT"], "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    with open(os.environ["ICEPICK_RESULT_OUT"], "w", encoding="utf-8") as handle:
        json.dump({"schema_version": "v1", "kind": "extract", "funcs": []}, handle)
"""

_SLEEP_THEN_WRITE = """
    import json
    import os
    import time

    time.sleep(float(os.environ.get("ICEPICK_SLEEP", "60")))
    with open(os.environ["ICEPICK_RESULT_OUT"], "w", encoding="utf-8") as handle:
        json.dump({"schema_version": "v1", "kind": "extract", "funcs": []}, handle)
"""

_TAGGED_WORKER = """
    import json
    import os
    import time

    # The marker records both ids, because they need not be equal: a venv
    # ``python.exe`` is a launcher that re-execs the real interpreter, so the pid
    # the supervisor owns (``Popen.pid``) is this child's ``ppid`` in that case,
    # and its own ``os.getpid()`` when the interpreter was exec'd directly.
    with open(os.environ["ICEPICK_MARKER_FILE"], "w", encoding="utf-8") as handle:
        handle.write(
            "%s|%s|%s" % (os.getppid(), os.getpid(), os.environ["ICEPICK_JOB_TAG"])
        )
    time.sleep(float(os.environ.get("ICEPICK_DELAY", "0")))
    document = {
        "schema_version": "v1",
        "kind": "extract",
        "generator": os.environ["ICEPICK_JOB_TAG"],
        "funcs": [],
    }
    with open(os.environ["ICEPICK_RESULT_OUT"], "w", encoding="utf-8") as handle:
        json.dump(document, handle)
"""

_TOUCH_FILE = """
    import pathlib

    pathlib.Path(ICEPICK_TARGET).write_text("started", encoding="utf-8")
"""


def _touch_worker(target: Path) -> list[str]:
    """A worker whose only job is to prove it was started (it must never run)."""
    return _worker(_TOUCH_FILE.replace("ICEPICK_TARGET", repr(str(target))))


# ---------------------------------------------------------------------------
# run_job — success passthrough
# ---------------------------------------------------------------------------
def test_run_job_passes_a_successful_fake_worker_through(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    idb = _write_idb(tmp_path / "sample.idb")
    out = tmp_path / "sample.idb.extract.json"
    report = tmp_path / "results" / "job.json"
    document = {
        "schema_version": "v1",
        "kind": "extract",
        "generator": "fake-worker",
        "funcs": [],
    }
    job = Job(
        idb,
        out=out,
        ida_home=fake_install,
        worker_argv=_worker(_WRITE_DOCUMENT),
        extra_env={
            "ICEPICK_DOCUMENT": json.dumps(document),
            "ICEPICK_RESULT_OUT": str(out),
        },
    )

    result = run_job(job, timeout=60.0, result_path=report)

    assert isinstance(result, JobResult)
    assert result.ok is True and result.failed is False
    assert result.error_code is None and result.error is None
    assert result.returncode == 0
    assert result.timed_out is False
    assert result.worker_pid and result.worker_pid > 0
    assert result.job_id == job.effective_id
    assert result.idb == str(idb)
    assert result.backend is Backend.IDALIB
    assert result.ida_home == os.path.normpath(str(fake_install))
    assert result.out == str(out)
    assert "fake-worker ok" in result.stdout
    assert result.duration_s >= 0.0
    # the worker's document is passed through untouched, and summarised
    assert json.loads(out.read_text(encoding="utf-8")) == document
    assert result.stats == {"funcs": 0, "decompiled_ok": 0, "decompile_failed": 0}
    # serialisation round-trip: JSON on disk either way
    assert result.to_dict()["ok"] is True
    assert json.loads(result.dumps())["error_code"] is None
    persisted = JobResult.from_dict(json.loads(report.read_text(encoding="utf-8")))
    assert persisted == result or persisted.to_dict() == result.to_dict()


def test_run_job_reads_the_documents_default_path(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    """``Job.out`` defaults to ``<IDB>.extract.json`` next to the IDB."""
    idb = _write_idb(tmp_path / "default.idb")
    out = output_path(Job(idb))
    assert out == tmp_path / "default.idb.extract.json"
    job = Job(
        idb,
        ida_home=fake_install,
        worker_argv=_worker(_WRITE_DOCUMENT),
        extra_env={
            "ICEPICK_DOCUMENT": json.dumps({"schema_version": "v1", "funcs": []}),
            "ICEPICK_RESULT_OUT": str(out),
        },
    )

    result = run_job(job)

    assert result.ok, result.error
    assert result.out == str(out)
    assert result.to_dict()["out"] == str(out)


# ---------------------------------------------------------------------------
# run_job — timeout owns the verdict and kills the worker
# ---------------------------------------------------------------------------
def test_run_job_kills_a_hung_worker_and_reports_timeout(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    idb = _write_idb(tmp_path / "hung.idb")
    out = tmp_path / "hung.idb.extract.json"
    job = Job(
        idb,
        out=out,
        ida_home=fake_install,
        timeout=1.5,
        worker_argv=_worker(_SLEEP_THEN_WRITE),
        extra_env={"ICEPICK_RESULT_OUT": str(out), "ICEPICK_SLEEP": "120"},
    )

    started = time.monotonic()
    result = run_job(job)  # Job.timeout is the effective limit
    elapsed = time.monotonic() - started

    assert result.failed is True
    assert result.timed_out is True
    assert result.error_code is ErrorCode.TIMEOUT
    assert result.error_code == "TIMEOUT"  # StrEnum compares as its token
    assert result.error and "exceeded" in result.error
    assert elapsed < 60.0, "the supervisor must not wait out a hung worker"
    # the worker was killed before it could write anything
    assert not out.exists()
    assert result.returncode != 0
    # ... and the process is really gone, not merely abandoned
    pid = result.worker_pid
    assert pid
    deadline = time.monotonic() + 10.0
    while queue_module.pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert queue_module.pid_alive(pid) is False
    assert result.to_dict()["error_code"] == "TIMEOUT"


def test_run_job_timeout_argument_overrides_the_job_budget(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    idb = _write_idb(tmp_path / "slow.idb")
    out = tmp_path / "slow.json"
    job = Job(
        idb,
        out=out,
        ida_home=fake_install,
        timeout=600.0,
        worker_argv=_worker(_SLEEP_THEN_WRITE),
        extra_env={"ICEPICK_RESULT_OUT": str(out), "ICEPICK_SLEEP": "120"},
    )

    result = run_job(job, timeout=1.0)

    assert result.error_code is ErrorCode.TIMEOUT
    assert "1s" in (result.error or "")


# ---------------------------------------------------------------------------
# the environment rule: explicit IDADIR into the child
# ---------------------------------------------------------------------------
def test_child_env_carries_the_explicit_idadir(
    tmp_path: Path, isolated_env: Path, fake_install: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker echoes its own environment: IDADIR is ours, not the shell's."""
    idb = _write_idb(tmp_path / "env.idb")
    out = tmp_path / "env.json"
    echo = tmp_path / "child-env.json"
    stale = tmp_path / "IDA 9.3-stale"
    stale.mkdir(parents=True, exist_ok=True)  # exists, but is not an install
    monkeypatch.setenv("IDADIR", str(stale))  # a stale pin that must not survive
    monkeypatch.setenv("STALE_IDADIR", str(stale))
    job = Job(
        idb,
        out=out,
        ida_home=fake_install,
        worker_argv=_worker(_WRITE_ENV_ECHO),
        extra_env={
            "ICEPICK_ECHO_OUT": str(echo),
            "ICEPICK_RESULT_OUT": str(out),
            "ICEPICK_CHILD_MARKER": "from-the-job",
        },
    )

    result = run_job(job)

    assert result.ok, result.error
    payload = json.loads(echo.read_text(encoding="utf-8"))
    assert _norm(payload["IDADIR"]) == _norm(fake_install)
    assert _norm(payload["IDADIR"]) != _norm(stale)
    assert payload["ICEPICK_CHILD_MARKER"] == "from-the-job"
    # src/ leads PYTHONPATH so the worker can `import icepick` with no install
    assert _norm(payload["PYTHONPATH"].split(os.pathsep)[0]) == _norm(source_root())
    assert payload["argv"][0] == "-c"  # `python -c <snippet>` names itself "-c"


def test_build_worker_env_overwrites_an_inherited_idadir(
    tmp_path: Path, fake_install: Path
) -> None:
    job = Job(tmp_path / "x.idb", ida_home=fake_install)
    base = {
        "IDADIR": str(tmp_path / "IDA 9.3-stale"),
        "PYTHONPATH": str(tmp_path / "elsewhere"),
        "ICEPICK_KEEP": "1",
    }

    env, home = build_worker_env(job, base_env=base)

    assert home == os.path.normpath(str(fake_install))
    assert env["IDADIR"] == os.path.normpath(str(fake_install))
    assert env["ICEPICK_KEEP"] == "1"  # unrelated variables are inherited
    assert env["PYTHONPATH"].split(os.pathsep) == [
        str(source_root()),
        str(tmp_path / "elsewhere"),
    ]
    # the mapping handed in was not aliased or mutated
    assert base["IDADIR"] == str(tmp_path / "IDA 9.3-stale")


def test_job_extra_env_reaches_the_child(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    idb = _write_idb(tmp_path / "extra.idb")
    out = tmp_path / "extra.json"
    echo = tmp_path / "extra-env.json"
    job = Job(
        idb,
        out=out,
        ida_home=fake_install,
        worker_argv=_worker(_WRITE_ENV_ECHO),
        extra_env={
            "ICEPICK_ECHO_OUT": str(echo),
            "ICEPICK_RESULT_OUT": str(out),
            "ICEPICK_CHILD_MARKER": "extra-env",
        },
    )

    result = run_job(job)

    assert result.ok, result.error
    payload = json.loads(echo.read_text(encoding="utf-8"))
    assert payload["ICEPICK_CHILD_MARKER"] == "extra-env"


def test_run_job_fails_fast_when_no_ida_home_can_be_resolved(
    tmp_path: Path, isolated_env: Path
) -> None:
    """No resolvable IDADIR: ``IDA_HOME_UNRESOLVED``, and no worker is started."""
    idb = _write_idb(tmp_path / "nohome.idb")
    marker = tmp_path / "worker-started.marker"
    job = Job(idb, worker_argv=_touch_worker(marker))

    result = run_job(job)

    assert result.error_code is ErrorCode.IDA_HOME_UNRESOLVED
    assert result.ida_home is None
    assert result.worker_pid is None
    assert not marker.exists()


# ---------------------------------------------------------------------------
# the licence gate: fail fast, before any worker
# ---------------------------------------------------------------------------
def test_check_license_fails_fast_when_idapro_is_unimportable(
    fake_install: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``idapro`` missing from the interpreter: the gate raises, it never hangs."""
    monkeypatch.setitem(sys.modules, "idapro", None)
    monkeypatch.setenv("IDADIR", "")  # recorded, so teardown undoes the pin
    with pytest.raises(ImportError):
        importlib.import_module("idapro")

    with pytest.raises(IDALicenseError) as excinfo:
        check_license(ida_home=fake_install)

    error = excinfo.value
    assert error.error_code is ErrorCode.IDA_LICENSE_ABSENT
    assert isinstance(error, queue_module.QueueError)
    assert "idapro" in str(error)


def test_check_license_pins_idadir_before_the_probe(fake_install: Path, monkeypatch) -> None:
    monkeypatch.setenv("IDADIR", "")
    seen: dict[str, str | None] = {}

    def probe() -> object:
        seen["idadir"] = os.environ.get("IDADIR")
        return object()

    assert check_license(ida_home=fake_install, importer=probe) == os.path.normpath(
        str(fake_install)
    )
    assert seen["idadir"] == os.path.normpath(str(fake_install))

    with pytest.raises(IDALicenseError):
        check_license(ida_home=fake_install, importer=lambda: None)


def test_run_job_licence_gate_is_decided_before_any_worker_starts(
    tmp_path: Path, isolated_env: Path, fake_install: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "idapro", None)
    monkeypatch.setenv("IDADIR", "")
    idb = _write_idb(tmp_path / "gated.idb")
    marker = tmp_path / "must-not-exist.marker"
    job = Job(
        idb,
        ida_home=fake_install,
        check_license=True,  # force the gate for a fake worker too
        worker_argv=_touch_worker(marker),
    )

    result = run_job(job)

    assert result.error_code is ErrorCode.IDA_LICENSE_ABSENT
    assert "idapro" in (result.error or "")
    assert result.worker_pid is None
    assert not marker.exists(), "the worker must never be started without a licence"


def test_run_job_skips_the_licence_gate_for_a_fake_worker(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    """``check_license=None`` (auto) is False when ``worker_argv`` is set."""
    idb = _write_idb(tmp_path / "auto.idb")
    out = tmp_path / "auto.json"
    job = Job(
        idb,
        out=out,
        ida_home=fake_install,
        worker_argv=_worker(_WRITE_DOCUMENT),
        extra_env={
            "ICEPICK_DOCUMENT": json.dumps({"schema_version": "v1", "funcs": []}),
            "ICEPICK_RESULT_OUT": str(out),
        },
    )

    result = run_job(job)

    assert job.check_license is None
    assert result.ok, result.error


# ---------------------------------------------------------------------------
# worker commands — backend naming
# ---------------------------------------------------------------------------
def test_ida_binary_names_the_backend_executable(tmp_path: Path) -> None:
    home = tmp_path / "IDA 9.5"
    suffix = ".exe" if os.name == "nt" else ""

    idat = ida_binary(home, Backend.IDAT)
    idalib = ida_binary(home, Backend.IDALIB)

    assert idat.name == f"idat{suffix}"
    assert idalib.name == f"idalib{suffix}"
    assert idat != idalib
    assert idat.parent == Path(str(home)) == idalib.parent
    # the backend may be named by its string value...
    assert ida_binary(str(home), "idat") == idat
    assert ida_binary(str(home), "idalib") == idalib
    # ...and idat is the default lane for this helper
    assert ida_binary(home) == idat


def test_ida_binary_rejects_an_unknown_backend(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ida_binary(tmp_path, "ida64")


# ---------------------------------------------------------------------------
# the error taxonomy — classify_failure spot-checks
# ---------------------------------------------------------------------------
def test_classify_failure_reports_success_and_missing_document() -> None:
    assert classify_failure(0, document={"funcs": []}) is None
    assert classify_failure(0, document={"funcs": [{"decompile_status": "ok"}]}) is None

    verdict = classify_failure(0, text="", document=None)
    assert verdict is not None
    code, message = verdict
    assert code is ErrorCode.WORKER_NO_RESULT
    assert "no readable result document" in message


@pytest.mark.parametrize(
    ("returncode", "text", "expected"),
    [
        (1, "IDA_BUSY: the database is locked by another process", ErrorCode.IDA_BUSY),
        (3, "idapro: no valid license found for this installation", ErrorCode.IDA_LICENSE_ABSENT),
        (2, "Fatal: IDA_HOME_UNRESOLVED - cannot pin IDADIR", ErrorCode.IDA_HOME_UNRESOLVED),
        (1, "ERROR: hexrays_init failed on this database", ErrorCode.DECOMPILE_FAILED),
        (1, "Traceback (most recent call last):\nValueError: boom", ErrorCode.WORKER_FAILED),
    ],
)
def test_classify_failure_maps_a_nonzero_exit(
    returncode: int, text: str, expected: ErrorCode
) -> None:
    verdict = classify_failure(returncode, text=text)

    assert verdict is not None
    code, message = verdict
    assert code is expected
    assert message  # never an empty message


def test_classify_failure_prefers_the_explicit_token() -> None:
    """An explicit taxonomy token wins over the looser phrase tables."""
    verdict = classify_failure(1, text="IDA_BUSY: no license, database is locked")

    assert verdict is not None
    assert verdict[0] is ErrorCode.IDA_BUSY


def test_classify_failure_maps_worker_failure_message() -> None:
    verdict = classify_failure(7, text="\n\n  something exploded  \nmore noise")

    assert verdict == (ErrorCode.WORKER_FAILED, "worker exited with code 7: something exploded")


def test_classify_failure_timeout_owns_the_verdict() -> None:
    verdict = classify_failure(0, text="whatever", timed_out=True)

    assert verdict is not None
    code, message = verdict
    assert code is ErrorCode.TIMEOUT
    assert "killed" in message


def test_classify_failure_uses_the_document_for_a_zero_exit() -> None:
    all_failed = {
        "funcs": [
            {"decompile_status": "failed"},
            {"decompile_status": "too_big"},
        ]
    }
    mixed = {"funcs": [{"decompile_status": "failed"}, {"decompile_status": "ok"}]}

    verdict = classify_failure(0, document=all_failed)
    assert verdict is not None
    code, message = verdict
    assert code is ErrorCode.DECOMPILE_FAILED
    assert "2 function(s)" in message
    assert classify_failure(0, document=mixed) is None


def test_taxonomy_tokens_are_enumerated() -> None:
    assert ErrorCode.TIMEOUT not in queue_module.EXPLICIT_CODE_TOKENS  # would match "TimeoutError"
    assert ErrorCode.IDA_LICENSE_ABSENT in queue_module.EXPLICIT_CODE_TOKENS
    assert ErrorCode.IDA_BUSY in queue_module.EXPLICIT_CODE_TOKENS
    assert first_line("\n  first real line  \nsecond") == "first real line"
    assert first_line("") == ""


# ---------------------------------------------------------------------------
# whole-job taxonomy through run_job
# ---------------------------------------------------------------------------
def test_run_job_rejects_a_malformed_job(tmp_path: Path, isolated_env: Path, fake_install: Path) -> None:
    missing = run_job(Job(tmp_path / "missing.idb", ida_home=fake_install, check_license=False))
    assert missing.error_code is ErrorCode.BAD_REQUEST
    assert "no such IDB" in (missing.error or "")
    assert missing.worker_pid is None

    idb = _write_idb(tmp_path / "bad-timeout.idb")
    job = Job(idb, ida_home=fake_install, check_license=False)
    for limit in (0, -1.0):
        result = run_job(job, timeout=limit)
        assert result.error_code is ErrorCode.BAD_REQUEST
        assert "timeout" in (result.error or "")

    with pytest.raises(TypeError):
        run_job(cast(Any, "not a job"))


def test_run_job_reports_launch_failed_for_an_unstartable_worker(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    idb = _write_idb(tmp_path / "launch.idb")
    job = Job(
        idb,
        ida_home=fake_install,
        worker_argv=[str(tmp_path / "no-such-worker.exe")],
    )

    result = run_job(job)

    assert result.error_code is ErrorCode.LAUNCH_FAILED
    assert "cannot start worker" in (result.error or "")
    assert result.worker_pid is None


def test_run_job_reports_worker_failed_and_worker_no_result(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    idb = _write_idb(tmp_path / "silent.idb")
    out = tmp_path / "silent.json"

    crashed = run_job(
        Job(
            idb,
            out=out,
            ida_home=fake_install,
            worker_argv=_worker("import sys\nsys.stderr.write('kaboom\\n')\nsys.exit(3)\n"),
        )
    )
    assert crashed.error_code is ErrorCode.WORKER_FAILED
    assert "kaboom" in (crashed.stderr or "")

    silent = run_job(
        Job(idb, out=out, ida_home=fake_install, worker_argv=_worker("pass\n"))
    )
    assert silent.error_code is ErrorCode.WORKER_NO_RESULT
    assert str(out) in (silent.error or "")
    assert silent.stdout == "" and silent.stderr == ""


# ---------------------------------------------------------------------------
# Supervisor.submit — two jobs, two isolated workers
# ---------------------------------------------------------------------------
def _tagged_job(
    tmp_path: Path,
    fake_install: Path,
    *,
    tag: str,
    job_id: str,
    delay: float,
) -> tuple[Job, Path, Path]:
    out = tmp_path / f"{tag}.extract.json"
    marker = tmp_path / f"{tag}.marker"
    idb = _write_idb(tmp_path / f"{tag}.idb")
    job = Job(
        idb,
        out=out,
        job_id=job_id,
        ida_home=fake_install,
        worker_argv=_worker(_TAGGED_WORKER),
        extra_env={
            "ICEPICK_RESULT_OUT": str(out),
            "ICEPICK_MARKER_FILE": str(marker),
            "ICEPICK_JOB_TAG": tag,
            "ICEPICK_DELAY": str(delay),
        },
    )
    return job, out, marker


def test_supervisor_submit_keeps_two_jobs_isolated(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    slow, slow_out, slow_marker = _tagged_job(
        tmp_path, fake_install, tag="slow", job_id="job-slow", delay=1.5
    )
    fast, fast_out, fast_marker = _tagged_job(
        tmp_path, fake_install, tag="fast", job_id="job-fast", delay=0.0
    )
    supervisor = Supervisor(max_workers=2)
    try:
        futures = [supervisor.submit(slow), supervisor.submit(fast)]
        results = supervisor.gather(futures)
    finally:
        supervisor.shutdown()

    # results come back in submission order, not completion order
    assert [result.job_id for result in results] == ["job-slow", "job-fast"]
    assert [result.out for result in results] == [str(slow_out), str(fast_out)]
    assert all(result.ok for result in results), [result.error for result in results]
    # two workers, two processes: no shared state, no second database in one process
    assert all(result.worker_pid for result in results)
    assert len({result.worker_pid for result in results}) == 2
    # every marker names the job that wrote it, plus the two pids it can report:
    # ``ppid`` and its own.  A venv ``python.exe`` re-execs the real interpreter, so
    # the process the supervisor owns is sometimes the child's own pid and sometimes
    # the parent it was re-exec'd from -- both are checked, neither is assumed.
    seen: dict[str, tuple[int, int]] = {}
    for tag, marker in (("slow", slow_marker), ("fast", fast_marker)):
        ppid_text, pid_text, seen_tag = marker.read_text(encoding="utf-8").split("|")
        assert seen_tag == tag
        seen[tag] = (int(ppid_text), int(pid_text))
    # one job, one process: the pid the supervisor owns for a job is the process that
    # job's worker ran in -- directly, or via the launcher it re-exec'd
    for result, tag in zip(results, ("slow", "fast")):
        assert result.worker_pid in seen[tag]
    # two live interpreters rather than two threads of one: distinct own pids, and
    # neither of them is the pytest process running this test
    own_pids = {pid for _ppid, pid in seen.values()}
    assert len(own_pids) == 2
    assert os.getpid() not in own_pids
    # each worker wrote exactly its own document
    for tag, out in (("slow", slow_out), ("fast", fast_out)):
        assert json.loads(out.read_text(encoding="utf-8"))["generator"] == tag
    assert not slow_marker.samefile(fast_marker)


def test_supervisor_submit_de_duplicates_job_ids(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    job, _out, _marker = _tagged_job(
        tmp_path, fake_install, tag="twin", job_id="same-id", delay=0.0
    )
    with Supervisor(max_workers=2) as supervisor:
        results = supervisor.gather([supervisor.submit(job), supervisor.submit(job)])

    assert [result.job_id for result in results] == ["same-id", "same-id-2"]
    assert all(result.ok for result in results), [result.error for result in results]


def test_supervisor_rejects_a_non_job_and_a_zero_width_pool(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        Supervisor().submit(cast(Any, "nope"))
    with pytest.raises(queue_module.QueueError):
        Supervisor(max_workers=0)


def test_run_queue_returns_reports_in_job_order(
    tmp_path: Path, isolated_env: Path, fake_install: Path
) -> None:
    first, _first_out, _first_marker = _tagged_job(
        tmp_path, fake_install, tag="first", job_id="q-1", delay=1.0
    )
    second, _second_out, _second_marker = _tagged_job(
        tmp_path, fake_install, tag="second", job_id="q-2", delay=0.0
    )
    report_path = tmp_path / "reports" / "run.json"

    results = run_queue([first, second], max_workers=2, result_path=report_path)

    assert [result.job_id for result in results] == ["q-1", "q-2"]
    assert all(result.ok for result in results), [result.error for result in results]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema"] == queue_module.REPORT_SCHEMA
    assert report["jobs"] == 2
    assert report["ok"] is True
    assert [entry["job_id"] for entry in report["results"]] == ["q-1", "q-2"]


def test_queue_module_is_ida_free() -> None:
    """The supervisor is stdlib-only: importing it pulls in no IDA module."""
    forbidden = {"idapro", "idaapi", "idc", "idautils", "ida_kernwin", "ida_hexrays"}
    leaked = sorted(
        name
        for name in sys.modules
        if name.split(".")[0] in forbidden or name.startswith("ida_")
    )
    assert leaked == []
    assert callable(queue_module.run_job)
    assert Path(queue_module.__file__).resolve() == (SRC / "icepick" / "queue.py").resolve()
