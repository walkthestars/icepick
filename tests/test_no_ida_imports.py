"""CI fence: the bridge never imports IDA, and ``src/`` is stdlib-only.

This is the contract that makes U-IDA1 fully CI-green without IDA installed:
anything in ``src/`` that reaches for ``idaapi``/``idapro``/``ida_*`` fails
here, before it can poison a test run or a worker process.

One deliberate carve-out (U-IDA2): :mod:`icepick.extract` **is** the IDA-side
lane, and it hosts its ``idapro``/``idaapi``/``idc``/``idautils`` imports inside
``import_ida()`` — they run only when extraction actually runs, so importing the
module stays IDA-free.  :data:`ALLOWED_IDA_HOSTS` names exactly that file; every
other module in ``src/`` still fails here on the first ``ida*`` import.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SRC_FILES = sorted(SRC.rglob("*.py"))

#: import roots that only exist inside an IDA process.
FORBIDDEN_ROOTS = {"idapro", "idaapi", "idc", "idautils", "ida_kernwin", "ida_hexrays"}

#: Deliberate carve-out (U-IDA2): the one module allowed to host IDA imports.
#: Its IDA imports sit inside ``import_ida()`` and run only when extraction
#: runs; the module-level check in the parametrised test keeps it that way.
#: Exactly one file, by design.
ALLOWED_IDA_HOSTS = frozenset({(SRC / "icepick" / "extract.py").resolve()})

def _is_forbidden(module: str) -> bool:
    root = (module or "").split(".")[0]
    if not root:
        return False
    return root in FORBIDDEN_ROOTS or root.startswith("ida_") or root == "idapython"


def _imported_modules(tree: ast.AST):
    """Yield ``(dotted_module_name, lineno)`` for every import-ish node."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative import: stays inside icepick
            if node.module:
                yield node.module, node.lineno
            for alias in node.names:
                yield f"{node.module or ''}.{alias.name}".lstrip("."), node.lineno
        elif isinstance(node, ast.Call):
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name not in {"__import__", "import_module"} or not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if name == "import_module" and arg.value.startswith("."):
                    continue
                yield arg.value, node.lineno


def _module_level_imports(tree: ast.Module):
    """Yield ``(module, lineno)`` for imports executed at module-import time.

    Anything inside a function or class body is deferred and therefore ignored —
    which is exactly the shape the allowlisted host must keep.
    """
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield from _imported_modules(node)
            continue
        stack.extend(ast.iter_child_nodes(node))


def test_src_tree_is_present():
    assert SRC.is_dir(), "src/ package directory missing"
    assert SRC_FILES, "no python files found under src/"
    assert (SRC / "icepick" / "schema.py").is_file()
    assert (SRC / "icepick" / "ingest.py").is_file()


@pytest.mark.parametrize("path", SRC_FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_ida_imports_anywhere_in_src(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    if path.resolve() in ALLOWED_IDA_HOSTS:
        # The carve-out is narrow: even here the IDA imports must stay *deferred*
        # to run time, never executed while the module is imported.
        module_level = [
            f"{path.relative_to(ROOT)}:{lineno}: module-level IDA import {module!r}"
            for module, lineno in _module_level_imports(tree)
            if _is_forbidden(module)
        ]
        assert not module_level, (
            "the allowlisted IDA host must defer its IDA imports to run time "
            "(move them inside import_ida()):\n" + "\n".join(module_level)
        )
        return
    offenders = [
        f"{path.relative_to(ROOT)}:{lineno}: imports {module!r}"
        for module, lineno in _imported_modules(tree)
        if _is_forbidden(module)
    ]
    assert not offenders, "IDA imports are forbidden in src/:\n" + "\n".join(offenders)


def test_no_ida_module_is_importable_from_bridge():
    """Importing the bridge must not drag any IDA module into ``sys.modules``."""
    import icepick.cli  # noqa: F401
    import icepick.ingest  # noqa: F401
    import icepick.schema  # noqa: F401

    leaked = sorted(name for name in sys.modules if _is_forbidden(name) and "ida" != name)
    assert not leaked, f"IDA modules leaked into sys.modules: {leaked}"


def test_src_uses_stdlib_only():
    """Every non-relative import in ``src/`` must be stdlib or ``icepick``."""
    offenders: list[str] = []
    for path in SRC_FILES:
        allowed_host = path.resolve() in ALLOWED_IDA_HOSTS
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for module, lineno in _imported_modules(tree):
            root = module.split(".")[0]
            if not root or root.startswith("icepick"):
                continue
            if root in sys.stdlib_module_names:
                continue
            # The allowlisted IDA host may import IDA (that is its whole job) and
            # nothing else that is non-stdlib.
            if allowed_host and _is_forbidden(root):
                continue
            offenders.append(
                f"{path.relative_to(ROOT)}:{lineno}: non-stdlib import {module!r}"
            )
    assert not offenders, "src/ must be stdlib-only:\n" + "\n".join(offenders)


def test_no_ida_toolchain_paths_referenced():
    """No hard-coded IDA install paths or worker binary names in the bridge."""
    forbidden_substrings = ("ida64.exe", "idat.exe", "ida32.exe", "ida-mcp")
    offenders: list[str] = []
    for path in SRC_FILES:
        text = path.read_text(encoding="utf-8").lower()
        for needle in forbidden_substrings:
            if needle in text:
                offenders.append(f"{path.relative_to(ROOT)}: mentions {needle!r}")
    assert not offenders, "\n".join(offenders)


def test_ingest_and_schema_expose_the_documented_api():
    from icepick import ingest, schema

    assert schema.SCHEMA_VERSION == "v1"
    assert callable(schema.validate_extract)
    assert callable(schema.validate_labels)
    assert callable(ingest.ingest_extract)
    assert callable(ingest.ingest_manual)


# ---------------------------------------------------------------------------
# the carve-out must stay narrow
# ---------------------------------------------------------------------------
def test_allowlist_is_exactly_the_ida_hosted_extractor():
    assert len(ALLOWED_IDA_HOSTS) == 1
    host = next(iter(ALLOWED_IDA_HOSTS))
    assert host == (SRC / "icepick" / "extract.py").resolve()
    assert host.is_file()
    assert host in {path.resolve() for path in SRC_FILES}


def test_guard_still_rejects_ida_imports_anywhere_else():
    """A synthetic offender outside the allowlist is still caught."""
    fake = SRC / "icepick" / "not_the_ida_host.py"
    assert fake.resolve() not in ALLOWED_IDA_HOSTS
    tree = ast.parse("import idapro\nfrom idaapi import FLIRT\nimport idc\nimport json\n")
    offenders = [
        f"{fake.relative_to(ROOT)}:{lineno}: imports {module!r}"
        for module, lineno in _imported_modules(tree)
        if _is_forbidden(module)
    ]
    # idapro (1) + idaapi and idaapi.FLIRT (2) + idc (1); ``json`` is ignored.
    assert len(offenders) == 4


def test_module_level_import_check_sees_module_code_only():
    """The deferred-import check inspects module code, not function bodies."""
    assert list(_module_level_imports(ast.parse("import idapro\n"))) == [("idapro", 1)]
    assert list(_module_level_imports(ast.parse("def f():\n    import idapro\n"))) == []
