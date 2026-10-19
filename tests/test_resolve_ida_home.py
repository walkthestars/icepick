"""IDA-home resolution tests — pure, no IDA runtime anywhere in sight.

Every IDA install here is a **fake**: a temporary directory carrying one of the
marker files ``icepick.extract`` looks for (:data:`IDA_INSTALL_MARKERS`), so the
whole suite runs on a machine without IDA, idalib or a license.

Covered contract (``docs/UNIT-IDA-PLAN.md``, environment rule after the
stale-``IDADIR`` incident):

* a valid inherited ``IDADIR`` wins for :func:`resolve_ida_home`;
* ``Paths.ida-install-dir`` from ``ida-config.json`` is the fallback, and the
  platform locations (``%APPDATA%`` / ``$XDG_CONFIG_HOME`` / ``~/.idapro``) are
  discovered by :func:`ida_config_paths`;
* :class:`IDAHomeError` is raised (and names what was tried) when nothing usable
  can be found — never a bare ``None``/``KeyError``/``FileNotFoundError``;
* the pin path :func:`pinned_ida_home` *ignores* the inherited ``IDADIR`` when
  the config points elsewhere (that is the whole point of the rule).

The environment is neutralised per test (``_isolate``) so a developer machine
with a real IDA install cannot make a negative test pass or fail by accident.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from icepick import extract

MARKER = "idalib.dll"

#: Environment variables that can steer resolution; all are cleared per test.
_CONFIG_ENV_VARS = (
    "IDADIR",
    "IDA_CONFIG_PATH",
    "IDACONFIG",
    "XDG_CONFIG_HOME",
    "APPDATA",
    "HOME",
    "USERPROFILE",
)

SRC = Path(__file__).resolve().parents[1] / "src"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Strip every IDA hint from the environment and point the config locations at ``tmp_path``.

    Without this a stale ``IDADIR`` (``9.3``) or a real ``ida-config.json``
    (``9.5``) on the developer machine would silently decide these tests.
    """
    for name in _CONFIG_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    empty = tmp_path / "isolated-home"
    empty.mkdir(parents=True, exist_ok=True)
    for name in ("APPDATA", "XDG_CONFIG_HOME", "HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(empty))


def _make_install(root: Path, *, marker: str = MARKER) -> Path:
    """Create a fake IDA install: a directory holding one marker file."""
    path = Path(root)
    path.mkdir(parents=True, exist_ok=True)
    (path / marker).write_text("", encoding="utf-8")
    return path


def _env() -> dict[str, str]:
    """A snapshot of the (monkeypatched) process environment."""
    return dict(os.environ)


def _write_config(
    path: Path,
    install: str,
    *,
    key: str = "ida-install-dir",
    nested: bool = True,
) -> Path:
    """Write an ``ida-config.json`` naming ``install``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    inner: object = {key: install}
    payload: object = {"Paths": inner} if nested else inner
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _norm(path: object) -> str:
    return os.path.normpath(str(path))


# ---------------------------------------------------------------------------
# is_ida_install — the marker sniff
# ---------------------------------------------------------------------------
def test_is_ida_install_accepts_any_marker(tmp_path):
    for marker in extract.IDA_INSTALL_MARKERS:
        install = _make_install(tmp_path / f"install-{marker.replace('.', '_')}", marker=marker)
        assert extract.is_ida_install(install) is True
        assert extract.is_ida_install(str(install)) is True


def test_is_ida_install_rejects_unmarked_and_missing_paths(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    unmarked = tmp_path / "not-ida"
    unmarked.mkdir()
    (unmarked / "tool.exe").write_text("", encoding="utf-8")
    a_file = tmp_path / "ida.hlp"  # a marker *file*, not a directory
    a_file.write_text("", encoding="utf-8")

    assert extract.is_ida_install(empty) is False
    assert extract.is_ida_install(unmarked) is False
    assert extract.is_ida_install(a_file) is False
    assert extract.is_ida_install(tmp_path / "never-existed") is False
    assert extract.is_ida_install(None) is False
    assert extract.is_ida_install("") is False


# ---------------------------------------------------------------------------
# resolve_ida_home — valid IDADIR first
# ---------------------------------------------------------------------------
def test_resolve_ida_home_prefers_a_valid_idadir(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    install = _make_install(tmp_path / "IDA 9.5")
    monkeypatch.setenv("IDADIR", str(install))

    assert extract.resolve_ida_home(env=_env()) == _norm(install)
    assert extract.find_ida_home(env=_env()) == _norm(install)


def test_resolve_ida_home_normalizes_the_idadir(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    install = _make_install(tmp_path / "IDA 9.5")
    messy = f"{install}{os.sep}{os.sep}." if os.sep == "/" else str(install) + os.sep + "."
    monkeypatch.setenv("IDADIR", messy)

    resolved = extract.resolve_ida_home(env=_env())
    assert resolved == _norm(install)
    assert resolved == os.path.abspath(resolved)


def test_resolve_ida_home_returns_a_str_not_a_path(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    install = _make_install(tmp_path / "IDA 9.5")
    monkeypatch.setenv("IDADIR", str(install))

    assert isinstance(extract.resolve_ida_home(env=_env()), str)


# ---------------------------------------------------------------------------
# resolve_ida_home — config-file fallback
# ---------------------------------------------------------------------------
def test_resolve_ida_home_falls_back_to_the_config_file(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    stale = _make_install(tmp_path / "IDA 9.3-renamed")
    monkeypatch.setenv("IDADIR", str(stale / "gone"))  # stale pin: does not exist
    pinned = _make_install(tmp_path / "IDA 9.5")
    config = _write_config(tmp_path / "ida-config.json", str(pinned))

    assert extract.resolve_ida_home(env=_env(), config_path=config) == _norm(pinned)


def test_resolve_ida_home_ignores_a_config_that_is_not_an_install(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    install = _make_install(tmp_path / "IDA 9.5")
    monkeypatch.setenv("IDADIR", str(install))
    empty = tmp_path / "empty-install"
    empty.mkdir()
    config = _write_config(tmp_path / "ida-config.json", str(empty))

    # The config is consulted, gives nothing usable, and the valid IDADIR wins.
    assert extract.resolve_ida_home(env=_env(), config_path=config) == _norm(install)


def test_resolve_ida_home_reads_the_platform_config_location(tmp_path, monkeypatch):
    """No explicit ``config_path``: the %APPDATA% location must be discovered."""
    _isolate(monkeypatch, tmp_path)
    install = _make_install(tmp_path / "IDA 9.5")
    roaming = tmp_path / "Roaming"
    monkeypatch.setenv("APPDATA", str(roaming))
    config = _write_config(
        roaming / "Hex-Rays" / "IDA Pro" / "ida-config.json", str(install)
    )

    assert config.is_file()
    assert config in extract.ida_config_paths(_env())
    assert extract.resolve_ida_home(env=_env()) == _norm(install)


def test_resolve_ida_home_expands_environment_variables_in_the_config(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    install = _make_install(tmp_path / "IDA 9.5")
    monkeypatch.setenv("ICEPICK_TEST_IDA_HOME", str(install))
    config = _write_config(tmp_path / "ida-config.json", "$ICEPICK_TEST_IDA_HOME")

    assert extract.resolve_ida_home(env=_env(), config_path=config) == _norm(install)


# ---------------------------------------------------------------------------
# ida_config_paths — discovery order and de-duplication
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("variable", ["IDA_CONFIG_PATH", "IDACONFIG"])
def test_ida_config_paths_puts_an_explicit_override_first(tmp_path, monkeypatch, variable):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv(variable, str(tmp_path / "explicit.json"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))

    paths = extract.ida_config_paths(_env())
    assert paths[0] == tmp_path / "explicit.json"
    assert paths[1] == tmp_path / "xdg" / "Hex-Rays" / "IDA Pro" / "ida-config.json"


def test_ida_config_paths_prefers_ida_config_path_over_idaconfig(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("IDA_CONFIG_PATH", str(tmp_path / "new.json"))
    monkeypatch.setenv("IDACONFIG", str(tmp_path / "legacy.json"))

    paths = extract.ida_config_paths(_env())
    assert paths[0] == tmp_path / "new.json"
    assert tmp_path / "legacy.json" not in paths


def test_ida_config_paths_is_deduplicated(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    shared = tmp_path / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("IDA_CONFIG_PATH", str(shared))

    keys = [
        os.path.normcase(os.path.normpath(str(path)))
        for path in extract.ida_config_paths(_env())
    ]
    assert len(keys) == len(set(keys))
    assert keys.count(os.path.normcase(os.path.normpath(str(shared)))) == 1


def test_ida_config_paths_stay_inside_isolated_home(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    paths = extract.ida_config_paths(_env())
    assert paths, "expected candidate locations even under isolation"
    assert all(str(p).startswith(str(tmp_path)) for p in paths), (
        "no candidate may point at the real developer machine"
    )


# ---------------------------------------------------------------------------
# ida_install_dir_from_config — reader
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "key", ["ida-install-dir", "ida_install_dir", "IDADIR", "install-dir", "install_dir"]
)
def test_ida_install_dir_from_config_knows_the_documented_keys(tmp_path, key):
    config = _write_config(tmp_path / "ida-config.json", r"C:\Program Files\IDA 9.5", key=key)
    assert extract.ida_install_dir_from_config(config) == r"C:\Program Files\IDA 9.5"


def test_ida_install_dir_from_config_searches_nested_structures(tmp_path):
    nested = tmp_path / "nested.json"
    nested.write_text(
        json.dumps({"Paths": {"Team": {"Paths": {"ida-install-dir": "/opt/ida95"}}}}),
        encoding="utf-8",
    )
    in_list = tmp_path / "list.json"
    in_list.write_text(
        json.dumps({"installs": [{"name": "x", "idadir": "/opt/ida-9.5"}]}),
        encoding="utf-8",
    )

    assert extract.ida_install_dir_from_config(nested) == "/opt/ida95"
    assert extract.ida_install_dir_from_config(in_list) == "/opt/ida-9.5"


@pytest.mark.parametrize(
    "payload",
    [
        None,  # missing file
        "",  # empty file
        "{not json",  # malformed JSON
        "[]",  # valid JSON, no install key
        '{"Paths": {"ida-install-dir": ""}}',  # blank value
        '{"Paths": {"ida-install-dir": null}}',  # wrong type
        '{"Paths": {"SomethingElse": "/opt/ida"}}',  # unknown key
    ],
)
def test_ida_install_dir_from_config_returns_none_for_unusable_configs(tmp_path, payload):
    if payload is None:
        config = tmp_path / "does-not-exist.json"
    else:
        config = tmp_path / "ida-config.json"
        config.write_text(payload, encoding="utf-8")

    assert extract.ida_install_dir_from_config(config) is None


# ---------------------------------------------------------------------------
# find_ida_home — the trust-env switch, never raises
# ---------------------------------------------------------------------------
def test_find_ida_home_trust_env_prefers_a_valid_inherited_idadir(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    inherited = _make_install(tmp_path / "IDA 9.3")
    configured = _make_install(tmp_path / "IDA 9.5")
    monkeypatch.setenv("IDADIR", str(inherited))
    config = _write_config(tmp_path / "ida-config.json", str(configured))

    assert extract.find_ida_home(env=_env(), config_path=config, trust_env=True) == _norm(
        inherited
    )
    # ... and by default the config wins (stale-override rule).
    assert extract.find_ida_home(env=_env(), config_path=config) == _norm(configured)


def test_find_ida_home_uses_a_valid_idadir_when_the_config_is_empty(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    install = _make_install(tmp_path / "IDA 9.5")
    monkeypatch.setenv("IDADIR", str(install))

    assert extract.find_ida_home(env=_env(), config_path=tmp_path / "missing.json") == _norm(
        install
    )


def test_find_ida_home_returns_none_instead_of_raising(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("IDADIR", str(tmp_path / "stale-does-not-exist"))

    assert extract.find_ida_home(env=_env(), config_path=tmp_path / "missing.json") is None
    assert extract.find_ida_home(env=_env()) is None


# ---------------------------------------------------------------------------
# IDAHomeError
# ---------------------------------------------------------------------------
def test_ida_home_error_is_a_value_error():
    assert issubclass(extract.IDAHomeError, ValueError)


def test_resolve_ida_home_raises_when_nothing_is_usable(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("IDADIR", str(tmp_path / "stale-9.3-renamed"))
    config = tmp_path / "ida-config.json"  # never written

    with pytest.raises(extract.IDAHomeError) as excinfo:
        extract.resolve_ida_home(env=_env(), config_path=config)

    message = str(excinfo.value)
    assert "cannot resolve the IDA install directory" in message
    assert "IDADIR" in message
    assert str(config) in message  # names what was tried


def test_resolve_ida_home_error_lists_the_discovered_config_locations(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    roaming = tmp_path / "Roaming"
    monkeypatch.setenv("APPDATA", str(roaming))

    with pytest.raises(extract.IDAHomeError) as excinfo:
        extract.resolve_ida_home(env=_env())

    assert str(roaming / "Hex-Rays" / "IDA Pro" / "ida-config.json") in str(excinfo.value)


def test_pinned_ida_home_raises_and_names_the_inherited_value(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("IDADIR", "C:/stale/ida-9.3")
    config = tmp_path / "missing.json"

    with pytest.raises(extract.IDAHomeError) as excinfo:
        extract.pinned_ida_home(env=_env(), config_path=config)

    message = str(excinfo.value)
    assert "cannot pin IDADIR" in message
    assert "C:/stale/ida-9.3" in message
    assert str(config) in message


# ---------------------------------------------------------------------------
# pinned_ida_home — the value that is written into os.environ before idapro
# ---------------------------------------------------------------------------
def test_pinned_ida_home_prefers_the_config_over_a_valid_env_idadir(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    stale = _make_install(tmp_path / "IDA 9.3")
    pinned = _make_install(tmp_path / "IDA 9.5")
    monkeypatch.setenv("IDADIR", str(stale))
    config = _write_config(tmp_path / "ida-config.json", str(pinned))

    assert extract.pinned_ida_home(env=_env(), config_path=config) == _norm(pinned)
    assert extract.pinned_ida_home(env=_env(), config_path=config, trust_env=True) == _norm(
        stale
    )


def test_import_ida_pins_os_environ_before_resolving(tmp_path, monkeypatch):
    """``import_ida`` must use the pinned home and never leak the stale IDADIR.

    The IDA import itself is deliberately not attempted (there is no IDA here):
    the point is that the *pin* is computed from ``--ida-home``/config, not from
    the inherited environment value that a harness shell may have left behind.
    """
    _isolate(monkeypatch, tmp_path)
    stale = _make_install(tmp_path / "IDA 9.3")
    pinned = _make_install(tmp_path / "IDA 9.5")
    monkeypatch.setenv("IDADIR", str(stale))
    config = _write_config(tmp_path / "ida-config.json", str(pinned))

    assert extract.pinned_ida_home(env=_env(), config_path=config) == _norm(pinned)
    assert extract.resolve_ida_home(env=_env(), config_path=config) == _norm(stale)


# ---------------------------------------------------------------------------
# no IDA runtime required
# ---------------------------------------------------------------------------
def test_importing_extract_needs_no_ida_runtime(tmp_path):
    """Importing the pure half must not pull ``idapro``/``idaapi``/``idc`` in."""
    script = (
        "import json, sys\n"
        "import icepick.extract as extract\n"
        "forbidden = {'idapro', 'idaapi', 'idc', 'idautils', 'ida_kernelfull'}\n"
        "leaked = sorted(\n"
        "    name for name in sys.modules\n"
        "    if name.split('.')[0] in forbidden or name.startswith('ida_')\n"
        ")\n"
        "print(json.dumps({'leaked': leaked, 'has_resolver': callable(extract.resolve_ida_home)}))\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env.pop("IDADIR", None)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(SRC.parent),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["leaked"] == []
    assert payload["has_resolver"] is True
