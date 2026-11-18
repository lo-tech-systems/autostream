#!/usr/bin/env python3
"""retarget_patches.py -- rewrite test references after a name moves modules.

When a function or constant moves from one module to another, every test that
patches or reads it through the old module has to follow.  This tool does the
mechanical part from a mapping file and reports the references it cannot
rewrite so they can be edited by hand.

Mapping file (UTF-8, ``#`` starts a comment), one entry per line:

    old_module.old_name -> new_module.new_name  alias=local_name

Usage:

    python tools/retarget_patches.py --map FILE [--check] [--root tests]
                                     [--only PATH ...]

``--check`` only reports.  The exit status is 1 when any reference to an old
target remains (after the rewrite, or at all with ``--check``), 2 on a
mapping or alias error, and 0 otherwise.

``--only PATH`` (repeatable) limits the scan, the rewrite and the report to the
named files, each of which must exist under ``--root`` (exit status 2 if not).
It is for a name that more than one module takes over: the tests that use one
destination follow it now and the others later.

Forms rewritten, per mapping entry:

  * a string equal to ``old_module.old_name`` or starting with it and a dot
    (``patch("m.n")``, ``"m.n.attr"``): the prefix becomes the new target;
  * ``X.old_name`` where ``X`` is bound to the old module by ``import``: it
    becomes ``alias.new_name``, and ``import new_module as alias`` is added
    after the last top-level import when the file lacks it;
  * ``setattr`` / ``delattr`` of the monkeypatch fixture and ``patch.object``
    with ``(X, "old_name")``: the module argument becomes ``alias`` and the
    name string the new name;
  * ``from old_module import old_name [as a]``: the name leaves that
    statement (the statement goes when it is empty) and
    ``from new_module import new_name [as a]`` takes its place, with ``as``
    added when the name changed so the local binding is unchanged;
  * ``patch.multiple("old_module", old_name=...)``: module string and keyword
    follow when every keyword maps to the same new module, otherwise the call
    is reported.

Edits use syntax-tree positions and are applied from the bottom of the file
up, so formatting elsewhere is untouched.  A parenthesised multi-line import
that is rewritten is regenerated one name per line; comments inside it are
not kept.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path


class ToolError(Exception):
    """A mapping or alias problem that stops the run."""


@dataclass(frozen=True)
class Entry:
    old_module: str
    old_name: str
    new_module: str
    new_name: str
    alias: str

    @property
    def old(self) -> str:
        return f"{self.old_module}.{self.old_name}"

    @property
    def new(self) -> str:
        return f"{self.new_module}.{self.new_name}"


_LINE = re.compile(r"^(\S+)\s*->\s*(\S+)\s+alias=([A-Za-z_]\w*)$")


def parse_map(text: str) -> list[Entry]:
    entries: list[Entry] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _LINE.match(line)
        if not m:
            raise ToolError(f"mapping line {number}: expected 'old.name -> new.name alias=x': {raw!r}")
        old_module, _, old_name = m.group(1).rpartition(".")
        new_module, _, new_name = m.group(2).rpartition(".")
        if not (old_module and old_name and new_module and new_name):
            raise ToolError(f"mapping line {number}: both sides need module.name: {raw!r}")
        entries.append(Entry(old_module, old_name, new_module, new_name, m.group(3)))
    return entries


# ---------------------------------------------------------------------------
# Source positions and edits
# ---------------------------------------------------------------------------

@dataclass
class Edit:
    start: int
    end: int
    text: bytes


class Source:
    """Source bytes with a (line, utf-8 column) to offset table."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.starts = [0]
        for i, b in enumerate(data):
            if b == 0x0A:
                self.starts.append(i + 1)
        self.newline = b"\r\n" if b"\r\n" in data else b"\n"

    def offset(self, line: int, col: int) -> int:
        return self.starts[line - 1] + col

    def span(self, node: ast.AST) -> tuple[int, int]:
        return (self.offset(node.lineno, node.col_offset),
                self.offset(node.end_lineno, node.end_col_offset))

    def text(self, node: ast.AST) -> str:
        s, e = self.span(node)
        return self.data[s:e].decode("utf-8")


def apply_edits(data: bytes, edits: list[Edit]) -> bytes:
    ordered = sorted(edits, key=lambda e: (e.start, e.end), reverse=True)
    last_start = len(data) + 1
    for e in ordered:
        if e.end > last_start:
            raise ToolError("overlapping edits")
        data = data[:e.start] + e.text + data[e.end:]
        last_start = e.start
    return data


# ---------------------------------------------------------------------------
# Finding references
# ---------------------------------------------------------------------------

def _old_module_aliases(tree: ast.AST, old_module: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname and a.name == old_module:
                    names.add(a.asname)
                elif not a.asname and a.name == old_module:
                    names.add(a.name)
    return names


def _module_bindings(tree: ast.Module) -> dict[str, str]:
    """Names bound at module level, mapped to a short description."""
    out: dict[str, str] = {}

    def bind(name: str, what: str) -> None:
        out.setdefault(name, what)

    def targets(t: ast.AST, what: str) -> None:
        if isinstance(t, ast.Name):
            bind(t.id, what)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                targets(e, what)

    def walk(body) -> None:
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bind(st.name, "definition")
            elif isinstance(st, ast.Assign):
                for t in st.targets:
                    targets(t, "assignment")
            elif isinstance(st, (ast.AnnAssign, ast.AugAssign)):
                targets(st.target, "assignment")
            elif isinstance(st, ast.Import):
                for a in st.names:
                    bind(a.asname or a.name.split(".")[0], f"import:{a.name}")
            elif isinstance(st, ast.ImportFrom):
                for a in st.names:
                    bind(a.asname or a.name, "from-import")
            elif isinstance(st, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                walk(st.body)
                walk(st.orelse)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                walk(st.body)
            elif isinstance(st, ast.Try):
                walk(st.body)
                for h in st.handlers:
                    walk(h.body)
                walk(st.orelse)
                walk(st.finalbody)

    walk(tree.body)
    return out


_MULTIPLE_OPTIONS = {"spec", "create", "spec_set", "autospec", "new_callable"}


def _is_patch(func: ast.AST) -> bool:
    return (isinstance(func, ast.Name) and func.id == "patch") or (
        isinstance(func, ast.Attribute) and func.attr == "patch"
    )


def _patch_style_call(call: ast.Call) -> str | None:
    """'object' for patch.object, 'setattr'/'delattr' for monkeypatch, else None."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr == "object" and _is_patch(func.value):
        return "object"
    if func.attr in ("setattr", "delattr"):
        base = func.value
        ident = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
        if ident in ("monkeypatch", "mp"):
            return func.attr
    return None


@dataclass
class Ref:
    kind: str          # handled kinds, or 'unhandled'
    node: ast.AST
    line: int
    note: str = ""


def _string_children_of_joined(tree: ast.AST) -> set[int]:
    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for sub in ast.walk(node):
                if sub is not node:
                    inside.add(id(sub))
    return inside


def _embedded(entry: Entry) -> re.Pattern:
    return re.compile(r"(?<![\w.])" + re.escape(entry.old) + r"(?!\w)")


def find_refs(tree: ast.Module, entry: Entry) -> list[Ref]:
    refs: list[Ref] = []
    aliases = _old_module_aliases(tree, entry.old_module)
    in_fstring = _string_children_of_joined(tree)
    embedded = _embedded(entry)
    claimed: set[int] = set()   # nodes consumed by a call-form match

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            style = _patch_style_call(node)
            if style and len(node.args) >= 2:
                first, second = node.args[0], node.args[1]
                if (isinstance(first, ast.Name) and first.id in aliases
                        and isinstance(second, ast.Constant) and second.value == entry.old_name):
                    refs.append(Ref("call-arg", node, node.lineno))
                    claimed.update((id(first), id(second)))
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "multiple" \
                    and _is_patch(node.func.value) and node.args \
                    and isinstance(node.args[0], ast.Constant) and node.args[0].value == entry.old_module \
                    and any(kw.arg == entry.old_name for kw in node.keywords):
                refs.append(Ref("multiple", node, node.lineno))
                claimed.add(id(node.args[0]))
            elif isinstance(node.func, ast.Name) and node.func.id in ("getattr", "setattr", "hasattr", "delattr") \
                    and len(node.args) >= 2 and isinstance(node.args[0], ast.Name) \
                    and node.args[0].id in aliases and isinstance(node.args[1], ast.Constant) \
                    and node.args[1].value == entry.old_name:
                refs.append(Ref("unhandled", node, node.lineno, f"{node.func.id}() with the old module"))
                claimed.update((id(node.args[0]), id(node.args[1])))
        elif isinstance(node, ast.ImportFrom) and node.module == entry.old_module and not node.level:
            if any(a.name == entry.old_name for a in node.names):
                refs.append(Ref("from-import", node, node.lineno))

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == entry.old_name \
                and isinstance(node.value, ast.Name) and node.value.id in aliases \
                and id(node.value) not in claimed:
            refs.append(Ref("attr", node, node.lineno))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in claimed:
            value = node.value
            if value == entry.old or value.startswith(entry.old + "."):
                kind = "unhandled" if id(node) in in_fstring else "string"
                refs.append(Ref(kind, node, node.lineno, "string inside an f-string" if kind == "unhandled" else ""))
            elif embedded.search(value):
                refs.append(Ref("unhandled", node, node.lineno, "old target inside a longer string"))
    return refs


# ---------------------------------------------------------------------------
# Edits
# ---------------------------------------------------------------------------

def _rewrite_literal(src: Source, node: ast.Constant, old: str, new: str) -> Edit | None:
    """Replace `old` by `new` in a string literal, if the result evaluates as expected."""
    start, end = src.span(node)
    seg = src.data[start:end].decode("utf-8")
    expected = new + node.value[len(old):] if node.value.startswith(old) else None
    if expected is None:
        return None
    candidate = seg.replace(old, new, 1)
    try:
        if ast.literal_eval(candidate) != expected:
            return None
    except (ValueError, SyntaxError):
        return None
    return Edit(start, end, candidate.encode("utf-8"))


def _import_statement(entry: Entry) -> str:
    if entry.alias == entry.new_module:
        return f"import {entry.new_module}"
    return f"import {entry.new_module} as {entry.alias}"


def _has_alias_import(tree: ast.Module, entry: Entry) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == entry.new_module and (a.asname or a.name) == entry.alias:
                    return True
    return False


def _alias_import_edit(src: Source, tree: ast.Module, entry: Entry) -> Edit | None:
    if _has_alias_import(tree, entry):
        return None
    bound = _module_bindings(tree).get(entry.alias)
    if bound is not None:
        raise ToolError(
            f"alias {entry.alias!r} collides with an existing module-level name ({bound}); "
            f"choose another alias for {entry.old}"
        )
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    text = _import_statement(entry).encode("utf-8")
    nl = src.newline
    if imports:
        last = max(imports, key=lambda n: n.end_lineno)
        _, end = src.span(last)
        return Edit(end, end, nl + text)
    body = tree.body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        _, end = src.span(body[0])
        return Edit(end, end, nl + nl + text)
    return Edit(0, 0, text + nl)


def _import_from_edit(src: Source, node: ast.ImportFrom, entry: Entry) -> Edit:
    start, end = src.span(node)
    indent = " " * node.col_offset
    keep = [a for a in node.names if a.name != entry.old_name]
    moved = [a for a in node.names if a.name == entry.old_name]
    parts: list[str] = []
    if keep:
        items = [f"{a.name} as {a.asname}" if a.asname else a.name for a in keep]
        if node.lineno != node.end_lineno:
            inner = "".join(f"{indent}    {i},\n" for i in items)
            parts.append(f"from {node.module} import (\n{inner}{indent})")
        else:
            parts.append(f"from {node.module} import {', '.join(items)}")
    for a in moved:
        local = a.asname or a.name
        spec = entry.new_name if local == entry.new_name else f"{entry.new_name} as {local}"
        parts.append(f"from {entry.new_module} import {spec}")
    text = ("\n" + indent).join(parts)
    if src.newline == b"\r\n":
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    return Edit(start, end, text.encode("utf-8"))


def edits_for(src: Source, tree: ast.Module, entry: Entry, refs: list[Ref], all_entries: list[Entry]):
    """Return (edits, count of references rewritten)."""
    edits: list[Edit] = []
    count = 0
    needs_alias_import = False
    for ref in refs:
        node = ref.node
        if ref.kind == "string":
            e = _rewrite_literal(src, node, entry.old, entry.new)
            if e:
                edits.append(e)
                count += 1
            else:
                ref.kind = "unhandled"
                ref.note = "string literal that cannot be rewritten safely"
        elif ref.kind == "attr":
            start, end = src.span(node)
            edits.append(Edit(start, end, f"{entry.alias}.{entry.new_name}".encode("utf-8")))
            needs_alias_import = True
            count += 1
        elif ref.kind == "call-arg":
            first, second = node.args[0], node.args[1]
            s1 = _rewrite_literal(src, second, entry.old_name, entry.new_name) \
                if entry.old_name != entry.new_name else None
            if entry.old_name != entry.new_name and not s1:
                ref.kind = "unhandled"
                ref.note = "name string that cannot be rewritten safely"
                continue
            fs, fe = src.span(first)
            edits.append(Edit(fs, fe, entry.alias.encode("utf-8")))
            if s1:
                edits.append(s1)
            needs_alias_import = True
            count += 1
        elif ref.kind == "from-import":
            edits.append(_import_from_edit(src, node, entry))
            count += 1
        elif ref.kind == "multiple":
            by_old = {(e.old_module, e.old_name): e for e in all_entries}
            named = [kw for kw in node.keywords if kw.arg and kw.arg not in _MULTIPLE_OPTIONS]
            mapped = [by_old.get((entry.old_module, kw.arg)) for kw in named]
            one_target = mapped and all(mapped) and len({m.new_module for m in mapped}) == 1
            if one_target and _rewrite_multiple(src, node, named, mapped, entry.old_module, edits):
                count += 1
            else:
                ref.kind = "unhandled"
                ref.note = "patch.multiple whose names do not all move to one module"
    if needs_alias_import:
        e = _alias_import_edit(src, tree, entry)
        if e:
            edits.append(e)
    return edits, count


def _rewrite_multiple(src: Source, node: ast.Call, named, mapped, old_module: str,
                      edits: list[Edit]) -> bool:
    first = node.args[0]
    s, e = src.span(first)
    seg = src.data[s:e].decode("utf-8")
    new_module = mapped[0].new_module
    new_seg = seg.replace(old_module, new_module, 1)
    try:
        if ast.literal_eval(new_seg) != new_module:
            return False
    except (ValueError, SyntaxError):
        return False
    edits.append(Edit(s, e, new_seg.encode("utf-8")))
    for kw, ent in zip(named, mapped):
        if ent.new_name != kw.arg:
            ks = src.offset(kw.lineno, kw.col_offset)
            edits.append(Edit(ks, ks + len(kw.arg.encode("utf-8")), ent.new_name.encode("utf-8")))
    return True


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

@dataclass
class FileResult:
    data: bytes
    counts: dict[Entry, int]
    unhandled: list[tuple[int, str]]
    references: dict[Entry, int]


def retarget_source(data: bytes, entries: list[Entry], check_only: bool = False) -> FileResult:
    counts = {e: 0 for e in entries}
    references = {e: 0 for e in entries}
    unhandled: list[tuple[int, str]] = []
    if check_only:
        tree = ast.parse(data)
        for entry in entries:
            refs = find_refs(tree, entry)
            references[entry] = len(refs)
            unhandled.extend((r.line, f"{entry.old}: {r.note or r.kind}") for r in refs)
        return FileResult(data, counts, sorted(set(unhandled)), references)
    for entry in entries:
        tree = ast.parse(data)
        src = Source(data)
        refs = find_refs(tree, entry)
        edits, count = edits_for(src, tree, entry, refs, entries)
        data = apply_edits(data, edits)
        counts[entry] = count
    tree = ast.parse(data)
    for entry in entries:
        for r in find_refs(tree, entry):
            unhandled.append((r.line, f"{entry.old}: {r.note or 'reference left in form ' + r.kind}"))
    return FileResult(data, counts, sorted(set(unhandled)), references)


def _only_files(root: Path, only: list[Path]) -> list[Path]:
    root_resolved = root.resolve()
    files: list[Path] = []
    for item in only:
        path = item if item.is_absolute() or item.exists() else root / item
        resolved = path.resolve()
        if not path.is_file() or root_resolved not in resolved.parents:
            raise ToolError(f"--only file not found under {root}: {item}")
        files.append(path)
    return sorted(set(files))


def run(map_file: Path, root: Path, check_only: bool, out=print,
        only: list[Path] | None = None) -> int:
    try:
        entries = parse_map(map_file.read_text(encoding="utf-8"))
        paths = _only_files(root, only) if only else sorted(root.rglob("*.py"))
    except ToolError as exc:
        out(f"error: {exc}")
        return 2
    per_entry_edits = {e: 0 for e in entries}
    per_entry_files = {e: 0 for e in entries}
    leftovers: list[str] = []
    for path in paths:
        if "__pycache__" in path.parts:
            continue
        data = path.read_bytes()
        try:
            result = retarget_source(data, entries, check_only)
        except ToolError as exc:
            out(f"error: {path}: {exc}")
            return 2
        except SyntaxError:
            continue
        for e in entries:
            n = result.references[e] if check_only else result.counts[e]
            if n:
                per_entry_edits[e] += n
                per_entry_files[e] += 1
        if not check_only and result.data != data:
            path.write_bytes(result.data)
        leftovers.extend(f"{path}:{line}: {note}" for line, note in result.unhandled)
    verb = "references" if check_only else "edits"
    for e in entries:
        out(f"{e.old} -> {e.new}: {per_entry_edits[e]} {verb} in {per_entry_files[e]} files")
    if leftovers:
        out("references left for a hand edit:" if not check_only else "references to the old targets:")
        for item in leftovers:
            out(f"  {item}")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Retarget test patches after names move modules.")
    parser.add_argument("--map", required=True, type=Path, help="mapping file")
    parser.add_argument("--check", action="store_true", help="report only; change nothing")
    parser.add_argument("--root", default="tests", type=Path, help="directory of test files (default: tests)")
    parser.add_argument("--only", action="append", type=Path, metavar="PATH",
                        help="rewrite and report only this file under --root (repeatable)")
    args = parser.parse_args(argv)
    return run(args.map, args.root, args.check, only=args.only)


if __name__ == "__main__":
    sys.exit(main())
