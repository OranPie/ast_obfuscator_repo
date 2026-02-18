#!/usr/bin/env python3
"""Single-file AST-based Python obfuscator.

Features
- Level presets (`--level 1..5`)
- Fine-grained toggles (`--[no-]rename`, `--[no-]strings`, `--[no-]ints`,
  `--[no-]floats`, `--[no-]bytes`, `--[no-]none`, `--[no-]bools`,
  `--[no-]flow`, `--[no-]attrs`, `--[no-]setattrs`, `--[no-]calls`,
  `--[no-]builtins`, `--[no-]wrap`)
- Type methods (`--string-mode`, `--int-mode`, `--float-mode`, `--bytes-mode`, `--none-mode`)
- Transformation order and density (`--order`, `--attr-mode`, `--attr-rate`, `--flow-rate`, `--flow-count`)
- Multiple transformation passes (`--passes`)
- Junk function injection (`--junk`, `--junk-position`)
- Deterministic builds (`--seed`)
- Rename map + obfumeta export (`--emit-map`, `--emit-meta`)
- Deobfuscation from obfumeta (`--deobfuscate --meta ...`)
- Optional syntax check and config explain (`--check`, `--explain`)

Note: this is obfuscation, not cryptographic protection.
"""

from __future__ import annotations

import argparse
import ast
import base64
import builtins
from datetime import datetime, timezone
import hashlib
import json
import keyword
import marshal
import random
import struct
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


BUILTIN_NAMES = set(dir(builtins))
PASS_TRANSFORMS = ("attrs", "setattrs", "calls", "bools", "ints", "floats", "bytes", "none", "flow")
METHOD_FAMILIES = ("attr", "setattr", "call", "builtin")

AVAILABLE_METHODS: dict[str, tuple[str, ...]] = {
    "attr": (
        "getattr",
        "builtins_getattr",
        "operator_attrgetter",
        "lambda_getattr",
        "globals_getattr",
        "locals_getattr",
    ),
    "setattr": (
        "setattr",
        "delattr",
        "builtins_setattr",
        "builtins_delattr",
        "lambda_setattr",
        "lambda_delattr",
    ),
    "call": (
        "helper_wrap",
        "lambda_wrap",
        "builtins_eval_call",
    ),
    "builtin": (
        "alias",
        "builtins_getattr_alias",
        "globals_lookup",
    ),
}

RISKY_METHODS = {"call": {"builtins_eval_call"}}

DYNAMIC_LEVEL_DEFAULTS: dict[str, dict[str, tuple[str, ...]]] = {
    "safe": {
        "attr": ("getattr", "builtins_getattr", "operator_attrgetter", "lambda_getattr"),
        "setattr": ("setattr", "delattr", "builtins_setattr", "builtins_delattr", "lambda_setattr"),
        "call": ("helper_wrap", "lambda_wrap"),
        "builtin": ("alias", "builtins_getattr_alias"),
    },
    "medium": {
        "attr": (
            "getattr",
            "builtins_getattr",
            "operator_attrgetter",
            "lambda_getattr",
            "globals_getattr",
        ),
        "setattr": (
            "setattr",
            "delattr",
            "builtins_setattr",
            "builtins_delattr",
            "lambda_setattr",
            "lambda_delattr",
        ),
        "call": ("helper_wrap", "lambda_wrap"),
        "builtin": ("alias", "builtins_getattr_alias", "globals_lookup"),
    },
    "heavy": {
        "attr": AVAILABLE_METHODS["attr"],
        "setattr": AVAILABLE_METHODS["setattr"],
        "call": AVAILABLE_METHODS["call"],
        "builtin": AVAILABLE_METHODS["builtin"],
    },
}


@dataclass
class ObfuscationConfig:
    level: int
    profile: str
    dynamic_level: str
    deobf_mode: str
    passes: int
    rename: bool
    strings: bool
    ints: bool
    floats: bool
    bytes_: bool
    none_values: bool
    bools: bool
    flow: bool
    attrs: bool
    setattrs: bool
    calls: bool
    builtins: bool
    wrap: bool
    junk: int
    junk_position: str
    string_mode: str
    int_mode: str
    float_mode: str
    bytes_mode: str
    bool_mode: str
    none_mode: str
    call_mode: str
    setattr_mode: str
    builtin_mode: str
    attr_mode: str
    flow_rate: float
    attr_rate: float
    setattr_rate: float
    call_rate: float
    builtin_rate: float
    flow_count: int
    string_chunk_min: int
    string_chunk_max: int
    transform_order: tuple[str, ...]
    keep_docstrings: bool
    preserve_names: set[str]
    preserve_attrs: set[str]
    seed: int | None
    emit_map: Path | None
    emit_meta: Path | None
    meta_include_source: bool
    dynamic_methods: dict[str, tuple[str, ...]]
    check: bool
    explain: bool


@dataclass
class ObfuscationStats:
    renamed: int = 0
    strings: int = 0
    ints: int = 0
    floats: int = 0
    bytes_: int = 0
    none_values: int = 0
    bools: int = 0
    flow_blocks: int = 0
    attrs: int = 0
    setattrs: int = 0
    calls: int = 0
    builtins: int = 0
    junk_functions: int = 0
    warnings: list[str] = field(default_factory=list)


class NameGenerator:
    def __init__(self, used: Iterable[str]) -> None:
        self.used = set(used)
        self.counter = 0

    def next_name(self) -> str:
        while True:
            name = f"_o{self.counter:x}"
            self.counter += 1
            if name not in self.used and not keyword.iskeyword(name):
                self.used.add(name)
                return name


class RenameCollector(ast.NodeVisitor):
    def __init__(self, preserve: set[str], generator: NameGenerator) -> None:
        self.preserve = preserve
        self.generator = generator
        self.mapping: dict[str, str] = {}
        self.class_depth = 0
        self.function_depth = 0

    def _allowed(self, name: str) -> bool:
        if (
            not name
            or name in self.preserve
            or name in BUILTIN_NAMES
            or keyword.iskeyword(name)
            or (name.startswith("__") and name.endswith("__"))
        ):
            return False
        return True

    def _bind(self, name: str) -> None:
        if self._allowed(name) and name not in self.mapping:
            self.mapping[name] = self.generator.next_name()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self.class_depth == 0 or self.function_depth > 0:
            self._bind(node.name)
        self.function_depth += 1
        self.visit(node.args)
        for dec in node.decorator_list:
            self.visit(dec)
        for stmt in node.body:
            self.visit(stmt)
        if node.returns:
            self.visit(node.returns)
        self.function_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self.class_depth == 0 or self.function_depth > 0:
            self._bind(node.name)
        self.class_depth += 1
        for base in node.bases:
            self.visit(base)
        for kw in node.keywords:
            self.visit(kw)
        for dec in node.decorator_list:
            self.visit(dec)
        for stmt in node.body:
            self.visit(stmt)
        self.class_depth -= 1

    def visit_arg(self, node: ast.arg) -> None:
        self._bind(node.arg)
        if node.annotation:
            self.visit(node.annotation)

    def visit_Name(self, node: ast.Name) -> None:
        if self.class_depth > 0 and self.function_depth == 0:
            return
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(node.id)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if isinstance(node.name, str):
            self._bind(node.name)
        if node.type:
            self.visit(node.type)
        for stmt in node.body:
            self.visit(stmt)

    def visit_Import(self, node: ast.Import) -> None:
        if self.class_depth > 0 and self.function_depth == 0:
            return
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            self._bind(bound)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self.class_depth > 0 and self.function_depth == 0:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            bound = alias.asname or alias.name
            self._bind(bound)


class Renamer(ast.NodeTransformer):
    def __init__(self, mapping: dict[str, str]) -> None:
        self.mapping = mapping
        self.class_depth = 0
        self.function_depth = 0

    def _maybe(self, name: str) -> str:
        return self.mapping.get(name, name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        if self.class_depth == 0 or self.function_depth > 0:
            node.name = self._maybe(node.name)
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        if self.class_depth == 0 or self.function_depth > 0:
            node.name = self._maybe(node.name)
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        if self.class_depth == 0 or self.function_depth > 0:
            node.name = self._maybe(node.name)
        self.class_depth += 1
        self.generic_visit(node)
        self.class_depth -= 1
        return node

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = self._maybe(node.arg)
        self.generic_visit(node)
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if self.class_depth > 0 and self.function_depth == 0:
            return node
        node.id = self._maybe(node.id)
        return node

    def visit_Global(self, node: ast.Global) -> ast.AST:
        node.names = [self._maybe(name) for name in node.names]
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.AST:
        node.names = [self._maybe(name) for name in node.names]
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        if isinstance(node.name, str):
            node.name = self._maybe(node.name)
        self.generic_visit(node)
        return node

    def visit_Import(self, node: ast.Import) -> ast.AST:
        if self.class_depth > 0 and self.function_depth == 0:
            return node
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            obf = self.mapping.get(bound)
            if obf:
                alias.asname = obf
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.AST:
        if self.class_depth > 0 and self.function_depth == 0:
            return node
        for alias in node.names:
            if alias.name == "*":
                continue
            bound = alias.asname or alias.name
            obf = self.mapping.get(bound)
            if obf:
                alias.asname = obf
        return node


class StringObfuscator(ast.NodeTransformer):
    def __init__(
        self,
        helper_name: str,
        rng: random.Random,
        keep_docstrings: bool,
        chunk_min: int,
        chunk_max: int,
        mode: str,
    ) -> None:
        self.helper_name = helper_name
        self.rng = rng
        self.keep_docstrings = keep_docstrings
        self.chunk_min = max(1, chunk_min)
        self.chunk_max = max(self.chunk_min, chunk_max)
        self.mode = mode
        self.changed = 0

    def _encode_chunks(self, value: str) -> list[tuple[int, list[int]]]:
        chunks: list[tuple[int, list[int]]] = []
        idx = 0
        while idx < len(value):
            hi = min(self.chunk_max, len(value) - idx)
            lo = min(self.chunk_min, hi)
            step = self.rng.randint(lo, hi)
            part = value[idx : idx + step]
            key = self.rng.randint(1, 255)
            chunks.append((key, [ord(ch) ^ key for ch in part]))
            idx += step
        return chunks

    def _xor_expr(self, value: str) -> ast.AST:
        chunks = self._encode_chunks(value)
        encoded_nodes: list[ast.expr] = []
        for key, values in chunks:
            encoded_nodes.append(
                ast.Tuple(
                    elts=[
                        ast.Constant(key),
                        ast.Tuple(elts=[ast.Constant(v) for v in values], ctx=ast.Load()),
                    ],
                    ctx=ast.Load(),
                )
            )
        return ast.Call(
            func=ast.Name(id=self.helper_name, ctx=ast.Load()),
            args=[ast.Constant(0), ast.Tuple(elts=encoded_nodes, ctx=ast.Load())],
            keywords=[],
        )

    def _b85_expr(self, value: str) -> ast.AST:
        payload = base64.b85encode(value.encode("utf-8")).decode("ascii")
        return ast.Call(
            func=ast.Name(id=self.helper_name, ctx=ast.Load()),
            args=[ast.Constant(1), ast.Constant(payload)],
            keywords=[],
        )

    def _reverse_expr(self, value: str) -> ast.AST:
        return ast.Call(
            func=ast.Name(id=self.helper_name, ctx=ast.Load()),
            args=[ast.Constant(2), ast.Constant(value[::-1])],
            keywords=[],
        )

    def _leaf_expr(self, value: str, mode: str) -> ast.AST:
        if mode == "b85":
            return self._b85_expr(value)
        if mode == "reverse":
            return self._reverse_expr(value)
        return self._xor_expr(value)

    def _split_expr(self, value: str) -> ast.AST:
        if len(value) <= 1:
            return self._leaf_expr(value, "xor")
        parts: list[str] = []
        idx = 0
        remaining = len(value)
        while remaining > 0:
            max_step = min(self.chunk_max, remaining)
            min_step = min(self.chunk_min, max_step)
            step = self.rng.randint(min_step, max_step)
            parts.append(value[idx : idx + step])
            idx += step
            remaining -= step
        if len(parts) == 1:
            return self._leaf_expr(parts[0], "xor")

        exprs: list[ast.AST] = []
        for part in parts:
            leaf_mode = self.rng.choice(("xor", "b85", "reverse"))
            exprs.append(self._leaf_expr(part, leaf_mode))

        out = exprs[0]
        for nxt in exprs[1:]:
            out = ast.BinOp(left=out, op=ast.Add(), right=nxt)
        return out

    def _obf_expr(self, value: str) -> ast.AST:
        mode = self.mode
        if mode == "mixed":
            mode = self.rng.choice(("xor", "b85", "reverse", "split"))
        self.changed += 1
        if mode == "split":
            return self._split_expr(value)
        return self._leaf_expr(value, mode)

    def _visit_body(self, body: list[ast.stmt]) -> list[ast.stmt]:
        out: list[ast.stmt] = []
        for idx, stmt in enumerate(body):
            if (
                idx == 0
                and self.keep_docstrings
                and isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            ):
                out.append(stmt)
                continue
            out.append(self.visit(stmt))
        return out

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body = self._visit_body(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.decorator_list = [self.visit(dec) for dec in node.decorator_list]
        if node.returns:
            node.returns = self.visit(node.returns)
        node.body = self._visit_body(node.body)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.decorator_list = [self.visit(dec) for dec in node.decorator_list]
        if node.returns:
            node.returns = self.visit(node.returns)
        node.body = self._visit_body(node.body)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.bases = [self.visit(base) for base in node.bases]
        node.keywords = [self.visit(kw) for kw in node.keywords]
        node.decorator_list = [self.visit(dec) for dec in node.decorator_list]
        node.body = self._visit_body(node.body)
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str) and node.value:
            return ast.copy_location(self._obf_expr(node.value), node)
        return node

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        # f-strings require literal text chunks inside JoinedStr.
        node.values = [
            self.visit(part) if isinstance(part, ast.FormattedValue) else part
            for part in node.values
        ]
        return node


class IntObfuscator(ast.NodeTransformer):
    def __init__(self, rng: random.Random, mode: str) -> None:
        self.rng = rng
        self.mode = mode
        self.changed = 0

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, bool) or not isinstance(node.value, int):
            return node

        value = node.value
        mode = self.mode
        if mode == "mixed":
            mode = self.rng.choice(("xor", "arith", "split"))

        if mode == "xor":
            key = self.rng.randint(1, 2**15)
            expr: ast.expr = ast.BinOp(
                left=ast.Constant(value ^ key),
                op=ast.BitXor(),
                right=ast.Constant(key),
            )
        elif mode == "arith":
            key = self.rng.randint(1, 1000)
            expr = ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value + key),
                    op=ast.Sub(),
                    right=ast.Constant(key),
                ),
                op=ast.Add(),
                right=ast.Constant(0),
            )
        else:
            pivot = self.rng.randint(-5000, 5000)
            expr = ast.BinOp(
                left=ast.Constant(pivot),
                op=ast.Add(),
                right=ast.Constant(value - pivot),
            )

        self.changed += 1
        return ast.copy_location(expr, node)


class FloatObfuscator(ast.NodeTransformer):
    def __init__(self, rng: random.Random, mode: str) -> None:
        self.rng = rng
        self.mode = mode
        self.changed = 0

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not isinstance(node.value, float):
            return node
        value = node.value
        if value != value or value in (float("inf"), float("-inf")):
            return node

        mode = self.mode
        if mode == "mixed":
            mode = self.rng.choice(("hex", "struct"))

        if mode == "struct":
            hex_bytes = struct.pack("!d", value).hex()
            mod = ast.Call(
                func=ast.Name(id="__import__", ctx=ast.Load()),
                args=[ast.Constant("struct")],
                keywords=[],
            )
            unpack = ast.Call(
                func=ast.Attribute(value=mod, attr="unpack", ctx=ast.Load()),
                args=[
                    ast.Constant("!d"),
                    ast.Call(
                        func=ast.Attribute(value=ast.Name(id="bytes", ctx=ast.Load()), attr="fromhex", ctx=ast.Load()),
                        args=[ast.Constant(hex_bytes)],
                        keywords=[],
                    ),
                ],
                keywords=[],
            )
            expr: ast.expr = ast.Subscript(
                value=unpack,
                slice=ast.Constant(0),
                ctx=ast.Load(),
            )
        else:
            expr = ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id="float", ctx=ast.Load()),
                    attr="fromhex",
                    ctx=ast.Load(),
                ),
                args=[ast.Constant(value.hex())],
                keywords=[],
            )

        self.changed += 1
        return ast.copy_location(expr, node)


class BytesObfuscator(ast.NodeTransformer):
    def __init__(self, rng: random.Random, mode: str) -> None:
        self.rng = rng
        self.mode = mode
        self.changed = 0

    def _leaf_expr(self, data: bytes, mode: str) -> ast.expr:
        if mode == "list":
            values = [ast.Constant(v) for v in data]
            expr: ast.expr = ast.Call(
                func=ast.Name(id="bytes", ctx=ast.Load()),
                args=[ast.Tuple(elts=values, ctx=ast.Load())],
                keywords=[],
            )
        else:
            key = self.rng.randint(1, 255)
            encoded = [ast.Constant(v ^ key) for v in data]
            target = ast.Name(id="_b", ctx=ast.Store())
            source = ast.Tuple(elts=encoded, ctx=ast.Load())
            gen = ast.GeneratorExp(
                elt=ast.BinOp(
                    left=ast.Name(id="_b", ctx=ast.Load()),
                    op=ast.BitXor(),
                    right=ast.Constant(key),
                ),
                generators=[ast.comprehension(target=target, iter=source, ifs=[], is_async=0)],
            )
            expr = ast.Call(
                func=ast.Name(id="bytes", ctx=ast.Load()),
                args=[gen],
                keywords=[],
            )
        return expr

    def _split_expr(self, data: bytes) -> ast.expr:
        if len(data) <= 1:
            return self._leaf_expr(data, "xor")
        pieces: list[bytes] = []
        idx = 0
        remaining = len(data)
        while remaining > 0:
            max_step = min(6, remaining)
            step = self.rng.randint(1, max_step)
            pieces.append(data[idx : idx + step])
            idx += step
            remaining -= step
        if len(pieces) == 1:
            return self._leaf_expr(pieces[0], "xor")

        exprs: list[ast.expr] = []
        for piece in pieces:
            leaf_mode = self.rng.choice(("xor", "list"))
            exprs.append(self._leaf_expr(piece, leaf_mode))
        out: ast.expr = exprs[0]
        for nxt in exprs[1:]:
            out = ast.BinOp(left=out, op=ast.Add(), right=nxt)
        return out

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not isinstance(node.value, bytes):
            return node

        mode = self.mode
        if mode == "mixed":
            mode = self.rng.choice(("xor", "list", "split"))
        if mode == "split":
            expr = self._split_expr(node.value)
        else:
            expr = self._leaf_expr(node.value, mode)

        self.changed += 1
        return ast.copy_location(expr, node)


class NoneObfuscator(ast.NodeTransformer):
    def __init__(self, rng: random.Random, mode: str) -> None:
        self.rng = rng
        self.mode = mode
        self.changed = 0

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if node.value is not None:
            return node

        mode = self.mode
        if mode == "mixed":
            mode = self.rng.choice(("lambda", "ifexpr"))

        if mode == "ifexpr":
            a = self.rng.randint(10, 999)
            b = a + self.rng.randint(1, 20)
            expr: ast.expr = ast.IfExp(
                test=ast.Compare(
                    left=ast.Constant(a),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(b)],
                ),
                body=ast.Constant(0),
                orelse=ast.Constant(None),
            )
        else:
            expr = ast.Call(
                func=ast.Lambda(
                    args=ast.arguments(
                        posonlyargs=[],
                        args=[],
                        kwonlyargs=[],
                        kw_defaults=[],
                        defaults=[],
                    ),
                    body=ast.Constant(None),
                ),
                args=[],
                keywords=[],
            )

        self.changed += 1
        return ast.copy_location(expr, node)


class BoolObfuscator(ast.NodeTransformer):
    def __init__(self, rng: random.Random, mode: str) -> None:
        self.rng = rng
        self.mode = mode
        self.changed = 0

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not isinstance(node.value, bool):
            return node

        mode = self.mode
        if mode == "mixed":
            mode = self.rng.choice(("compare", "xor"))

        if mode == "xor":
            left = self.rng.randint(10, 10000)
            right = left ^ (1 if node.value else 0)
            expr: ast.expr = ast.Call(
                func=ast.Name(id="bool", ctx=ast.Load()),
                args=[
                    ast.BinOp(
                        left=ast.Constant(left),
                        op=ast.BitXor(),
                        right=ast.Constant(right),
                    )
                ],
                keywords=[],
            )
        else:
            a = self.rng.randint(10, 9999)
            if node.value:
                b = a
            else:
                b = a + self.rng.randint(1, 100)
            expr = ast.Compare(
                left=ast.Constant(a),
                ops=[ast.Eq()],
                comparators=[ast.Constant(b)],
            )

        self.changed += 1
        return ast.copy_location(expr, node)


class AttributeLoadObfuscator(ast.NodeTransformer):
    def __init__(
        self,
        rng: random.Random,
        preserve_attrs: set[str],
        mode: str,
        rate: float,
        methods: tuple[str, ...],
    ) -> None:
        self.rng = rng
        self.preserve_attrs = preserve_attrs
        self.mode = mode
        self.rate = max(0.0, min(1.0, rate))
        self.methods = methods
        self.changed = 0

    def _attr_name_expr(self, attr: str) -> ast.expr:
        style = self.rng.choice(("plain", "join", "chr"))
        if style == "join" and len(attr) > 1:
            return ast.Call(
                func=ast.Attribute(value=ast.Constant(""), attr="join", ctx=ast.Load()),
                args=[ast.Tuple(elts=[ast.Constant(ch) for ch in attr], ctx=ast.Load())],
                keywords=[],
            )
        if style == "chr":
            return ast.Call(
                func=ast.Attribute(value=ast.Constant(""), attr="join", ctx=ast.Load()),
                args=[
                    ast.GeneratorExp(
                        elt=ast.Call(
                            func=ast.Name(id="chr", ctx=ast.Load()),
                            args=[ast.Name(id="_c", ctx=ast.Load())],
                            keywords=[],
                        ),
                        generators=[
                            ast.comprehension(
                                target=ast.Name(id="_c", ctx=ast.Store()),
                                iter=ast.Tuple(
                                    elts=[ast.Constant(ord(ch)) for ch in attr],
                                    ctx=ast.Load(),
                                ),
                                ifs=[],
                                is_async=0,
                            )
                        ],
                    )
                ],
                keywords=[],
            )
        return ast.Constant(attr)

    def _pick_method(self) -> str:
        explicit_map = {
            "getattr": "getattr",
            "builtins": "builtins_getattr",
            "attrgetter": "operator_attrgetter",
            "lambda": "lambda_getattr",
        }
        if self.mode in explicit_map:
            return explicit_map[self.mode]
        if self.methods:
            return self.rng.choice(self.methods)
        return "getattr"

    def _build_expr(self, obj: ast.expr, attr: str) -> ast.expr:
        method = self._pick_method()

        attr_expr = self._attr_name_expr(attr)
        if method == "builtins_getattr":
            builtins_mod = ast.Call(
                func=ast.Name(id="__import__", ctx=ast.Load()),
                args=[ast.Constant("builtins")],
                keywords=[],
            )
            return ast.Call(
                func=ast.Attribute(value=builtins_mod, attr="getattr", ctx=ast.Load()),
                args=[obj, attr_expr],
                keywords=[],
            )
        if method == "operator_attrgetter":
            op_mod = ast.Call(
                func=ast.Name(id="__import__", ctx=ast.Load()),
                args=[ast.Constant("operator")],
                keywords=[],
            )
            getter = ast.Call(
                func=ast.Attribute(value=op_mod, attr="attrgetter", ctx=ast.Load()),
                args=[attr_expr],
                keywords=[],
            )
            return ast.Call(func=getter, args=[obj], keywords=[])
        if method == "lambda_getattr":
            lam = ast.Lambda(
                args=ast.arguments(
                    posonlyargs=[],
                    args=[ast.arg(arg="_o"), ast.arg(arg="_n")],
                    kwonlyargs=[],
                    kw_defaults=[],
                    defaults=[],
                ),
                body=ast.Call(
                    func=ast.Name(id="getattr", ctx=ast.Load()),
                    args=[ast.Name(id="_o", ctx=ast.Load()), ast.Name(id="_n", ctx=ast.Load())],
                    keywords=[],
                ),
            )
            return ast.Call(func=lam, args=[obj, attr_expr], keywords=[])
        if method == "globals_getattr":
            return ast.Call(
                func=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(func=ast.Name(id="globals", ctx=ast.Load()), args=[], keywords=[]),
                        attr="get",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant("getattr"), ast.Name(id="getattr", ctx=ast.Load())],
                    keywords=[],
                ),
                args=[obj, attr_expr],
                keywords=[],
            )
        if method == "locals_getattr":
            # Local dict fallback form; ultimately resolves to builtin getattr.
            local_getattr = ast.Call(
                func=ast.Attribute(
                    value=ast.Call(func=ast.Name(id="locals", ctx=ast.Load()), args=[], keywords=[]),
                    attr="get",
                    ctx=ast.Load(),
                ),
                args=[ast.Constant("getattr")],
                keywords=[],
            )
            return ast.Call(
                func=ast.BoolOp(
                    op=ast.Or(),
                    values=[local_getattr, ast.Name(id="getattr", ctx=ast.Load())],
                ),
                args=[obj, attr_expr],
                keywords=[],
            )
        return ast.Call(
            func=ast.Name(id="getattr", ctx=ast.Load()),
            args=[obj, attr_expr],
            keywords=[],
        )

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        self.generic_visit(node)
        if not isinstance(node.ctx, ast.Load):
            return node
        if node.attr in self.preserve_attrs:
            return node
        if node.attr.startswith("__") and node.attr.endswith("__"):
            return node
        if self.rng.random() > self.rate:
            return node

        self.changed += 1
        replaced = self._build_expr(node.value, node.attr)
        return ast.copy_location(replaced, node)


class SetAttrRewriter(ast.NodeTransformer):
    def __init__(
        self,
        rng: random.Random,
        preserve_attrs: set[str],
        mode: str,
        rate: float,
        methods: tuple[str, ...],
    ) -> None:
        self.rng = rng
        self.preserve_attrs = preserve_attrs
        self.mode = mode
        self.rate = max(0.0, min(1.0, rate))
        self.methods = methods
        self.changed = 0

    def _allowed(self, attr: str) -> bool:
        if attr in self.preserve_attrs:
            return False
        if attr.startswith("__") and attr.endswith("__"):
            return False
        return True

    def _pick_set_method(self) -> str:
        explicit_map = {
            "setattr": "setattr",
            "builtins": "builtins_setattr",
            "lambda": "lambda_setattr",
        }
        if self.mode in explicit_map:
            return explicit_map[self.mode]
        choices = [m for m in self.methods if m.endswith("setattr")]
        if choices:
            return self.rng.choice(choices)
        return "setattr"

    def _pick_del_method(self) -> str:
        explicit_map = {
            "setattr": "delattr",
            "builtins": "builtins_delattr",
            "lambda": "lambda_delattr",
        }
        if self.mode in explicit_map:
            return explicit_map[self.mode]
        choices = [m for m in self.methods if m.endswith("delattr")]
        if choices:
            return self.rng.choice(choices)
        return "delattr"

    def _set_expr(self, obj: ast.expr, attr_name: str, value: ast.expr) -> ast.expr:
        method = self._pick_set_method()
        if method == "builtins_setattr":
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Call(func=ast.Name(id="__import__", ctx=ast.Load()), args=[ast.Constant("builtins")], keywords=[]),
                    attr="setattr",
                    ctx=ast.Load(),
                ),
                args=[obj, ast.Constant(attr_name), value],
                keywords=[],
            )
        if method == "lambda_setattr":
            lam = ast.Lambda(
                args=ast.arguments(
                    posonlyargs=[],
                    args=[ast.arg(arg="_o"), ast.arg(arg="_n"), ast.arg(arg="_v")],
                    kwonlyargs=[],
                    kw_defaults=[],
                    defaults=[],
                ),
                body=ast.Call(
                    func=ast.Name(id="setattr", ctx=ast.Load()),
                    args=[ast.Name(id="_o", ctx=ast.Load()), ast.Name(id="_n", ctx=ast.Load()), ast.Name(id="_v", ctx=ast.Load())],
                    keywords=[],
                ),
            )
            return ast.Call(func=lam, args=[obj, ast.Constant(attr_name), value], keywords=[])
        return ast.Call(
            func=ast.Name(id="setattr", ctx=ast.Load()),
            args=[obj, ast.Constant(attr_name), value],
            keywords=[],
        )

    def _del_expr(self, obj: ast.expr, attr_name: str) -> ast.expr:
        method = self._pick_del_method()
        if method == "builtins_delattr":
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Call(func=ast.Name(id="__import__", ctx=ast.Load()), args=[ast.Constant("builtins")], keywords=[]),
                    attr="delattr",
                    ctx=ast.Load(),
                ),
                args=[obj, ast.Constant(attr_name)],
                keywords=[],
            )
        if method == "lambda_delattr":
            lam = ast.Lambda(
                args=ast.arguments(
                    posonlyargs=[],
                    args=[ast.arg(arg="_o"), ast.arg(arg="_n")],
                    kwonlyargs=[],
                    kw_defaults=[],
                    defaults=[],
                ),
                body=ast.Call(
                    func=ast.Name(id="delattr", ctx=ast.Load()),
                    args=[ast.Name(id="_o", ctx=ast.Load()), ast.Name(id="_n", ctx=ast.Load())],
                    keywords=[],
                ),
            )
            return ast.Call(func=lam, args=[obj, ast.Constant(attr_name)], keywords=[])
        return ast.Call(
            func=ast.Name(id="delattr", ctx=ast.Load()),
            args=[obj, ast.Constant(attr_name)],
            keywords=[],
        )

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        self.generic_visit(node)
        if self.rng.random() > self.rate:
            return node
        if len(node.targets) != 1:
            return node
        target = node.targets[0]
        if not isinstance(target, ast.Attribute):
            return node
        if not self._allowed(target.attr):
            return node

        self.changed += 1
        call = self._set_expr(target.value, target.attr, node.value)
        return ast.copy_location(ast.Expr(value=call), node)

    def visit_Delete(self, node: ast.Delete) -> ast.AST:
        self.generic_visit(node)
        if self.rng.random() > self.rate:
            return node
        if not node.targets:
            return node
        if not all(isinstance(target, ast.Attribute) for target in node.targets):
            return node

        out: list[ast.stmt] = []
        for target in node.targets:
            assert isinstance(target, ast.Attribute)
            if not self._allowed(target.attr):
                return node
            self.changed += 1
            call = self._del_expr(target.value, target.attr)
            out.append(ast.copy_location(ast.Expr(value=call), node))
        return out


class CallObfuscator(ast.NodeTransformer):
    def __init__(
        self,
        rng: random.Random,
        helper_name: str,
        mode: str,
        rate: float,
        methods: tuple[str, ...],
    ) -> None:
        self.rng = rng
        self.helper_name = helper_name
        self.mode = mode
        self.rate = max(0.0, min(1.0, rate))
        self.methods = methods
        self.changed = 0

    def _kwargs_dict(self, keywords: list[ast.keyword]) -> ast.Dict:
        keys: list[ast.expr] = []
        values: list[ast.expr] = []
        for kw in keywords:
            if kw.arg is None:
                return ast.Dict(keys=[], values=[])
            keys.append(ast.Constant(kw.arg))
            values.append(kw.value)
        return ast.Dict(keys=keys, values=values)

    def _lambda_wrap(self, func: ast.expr, args: list[ast.expr], keywords: list[ast.keyword]) -> ast.expr:
        args_tuple = ast.Tuple(elts=args, ctx=ast.Load())
        kwargs_dict = self._kwargs_dict(keywords)
        lam = ast.Lambda(
            args=ast.arguments(
                posonlyargs=[],
                args=[ast.arg(arg="_f"), ast.arg(arg="_a"), ast.arg(arg="_k")],
                kwonlyargs=[],
                kw_defaults=[],
                defaults=[],
            ),
            body=ast.Call(
                func=ast.Name(id="_f", ctx=ast.Load()),
                args=[ast.Starred(value=ast.Name(id="_a", ctx=ast.Load()), ctx=ast.Load())],
                keywords=[ast.keyword(arg=None, value=ast.Name(id="_k", ctx=ast.Load()))],
            ),
        )
        return ast.Call(func=lam, args=[func, args_tuple, kwargs_dict], keywords=[])

    def _eval_wrap(self, func: ast.expr, args: list[ast.expr], keywords: list[ast.keyword]) -> ast.expr:
        args_tuple = ast.Tuple(elts=args, ctx=ast.Load())
        kwargs_dict = self._kwargs_dict(keywords)
        expr = ast.BinOp(
            left=ast.Constant("lambda f,a,k: f(*a, **k)"),
            op=ast.Add(),
            right=ast.Constant(""),
        )
        compiled_lam = ast.Call(
            func=ast.Name(id="eval", ctx=ast.Load()),
            args=[expr],
            keywords=[],
        )
        return ast.Call(func=compiled_lam, args=[func, args_tuple, kwargs_dict], keywords=[])

    def _pick_method(self) -> str:
        explicit_map = {
            "wrap": "helper_wrap",
            "lambda": "lambda_wrap",
            "eval": "builtins_eval_call",
        }
        if self.mode in explicit_map:
            return explicit_map[self.mode]
        if self.methods:
            return self.rng.choice(self.methods)
        return "helper_wrap"

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        if self.rng.random() > self.rate:
            return node
        if isinstance(node.func, ast.Name) and node.func.id == self.helper_name:
            return node
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            return node
        if any(kw.arg is None for kw in node.keywords):
            return node

        method = self._pick_method()
        if method == "lambda_wrap":
            replaced = self._lambda_wrap(node.func, node.args, node.keywords)
        elif method == "builtins_eval_call":
            replaced = self._eval_wrap(node.func, node.args, node.keywords)
        else:
            replaced = ast.Call(
                func=ast.Name(id=self.helper_name, ctx=ast.Load()),
                args=[
                    node.func,
                    ast.Tuple(elts=node.args, ctx=ast.Load()),
                    self._kwargs_dict(node.keywords),
                ],
                keywords=[],
            )
        self.changed += 1
        return ast.copy_location(replaced, node)


class BuiltinAliasTransformer(ast.NodeTransformer):
    def __init__(self, mapping: dict[str, str], rate: float, rng: random.Random) -> None:
        self.mapping = mapping
        self.rate = max(0.0, min(1.0, rate))
        self.rng = rng
        self.changed = 0

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if isinstance(node.ctx, ast.Load):
            alias = self.mapping.get(node.id)
            if alias and self.rng.random() <= self.rate:
                self.changed += 1
                return ast.copy_location(ast.Name(id=alias, ctx=ast.Load()), node)
        return node


class FlowObfuscator(ast.NodeTransformer):
    def __init__(
        self,
        rng: random.Random,
        keep_docstrings: bool,
        rate: float,
        max_count: int,
    ) -> None:
        self.rng = rng
        self.keep_docstrings = keep_docstrings
        self.rate = max(0.0, min(1.0, rate))
        self.max_count = max(1, max_count)
        self.changed = 0

    def _dead_if(self) -> ast.If:
        a = self.rng.randint(100, 999)
        b = a + self.rng.randint(1, 50)
        return ast.If(
            test=ast.Compare(
                left=ast.Constant(a),
                ops=[ast.Eq()],
                comparators=[ast.Constant(b)],
            ),
            body=[ast.Pass()],
            orelse=[],
        )

    def _inject(self, body: list[ast.stmt]) -> list[ast.stmt]:
        if self.rng.random() > self.rate:
            return body

        insert_at = 0
        if (
            self.keep_docstrings
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            insert_at = 1
        amount = self.rng.randint(1, self.max_count)
        for _ in range(amount):
            body.insert(insert_at, self._dead_if())
            self.changed += 1
        return body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AST-based Python obfuscator")
    parser.add_argument("input", type=Path, help="Input .py file")
    parser.add_argument("-o", "--output", type=Path, required=True, help="Output .py file")
    parser.add_argument("--level", type=int, choices=(1, 2, 3, 4, 5), default=2)
    parser.add_argument(
        "--profile",
        choices=("balanced", "stealth", "max"),
        default="balanced",
        help="Preset profile defaults (explicit flags still override)",
    )
    parser.add_argument(
        "--dynamic-level",
        choices=("safe", "medium", "heavy"),
        default="safe",
        help="Default dynamic method pool tier",
    )

    parser.add_argument("--passes", type=int, default=0, help="Extra transform passes (default from level)")
    parser.add_argument("--junk", type=int, default=-1, help="Inject N junk functions (default from level)")
    parser.add_argument(
        "--junk-position",
        choices=("top", "bottom", "random"),
        default="top",
        help="Where to place junk functions",
    )
    parser.add_argument(
        "--int-mode",
        choices=("mixed", "xor", "arith", "split"),
        default="mixed",
        help="Integer obfuscation style",
    )
    parser.add_argument(
        "--float-mode",
        choices=("mixed", "hex", "struct"),
        default="mixed",
        help="Float obfuscation style",
    )
    parser.add_argument(
        "--bytes-mode",
        choices=("mixed", "xor", "list", "split"),
        default="mixed",
        help="Bytes obfuscation style",
    )
    parser.add_argument(
        "--bool-mode",
        choices=("mixed", "compare", "xor"),
        default="mixed",
        help="Bool obfuscation style",
    )
    parser.add_argument(
        "--call-mode",
        choices=("mixed", "wrap", "lambda", "eval"),
        default="mixed",
        help="Call replacement style",
    )
    parser.add_argument(
        "--setattr-mode",
        choices=("mixed", "setattr", "builtins", "lambda"),
        default="mixed",
        help="Attribute write/delete replacement style",
    )
    parser.add_argument(
        "--builtin-mode",
        choices=("mixed", "alias", "getattr", "globals"),
        default="mixed",
        help="Builtin alias resolution style",
    )
    parser.add_argument(
        "--attr-mode",
        choices=("mixed", "getattr", "builtins", "attrgetter", "lambda"),
        default="mixed",
        help="Attribute load replacement style",
    )
    parser.add_argument(
        "--none-mode",
        choices=("mixed", "lambda", "ifexpr"),
        default="mixed",
        help="None obfuscation style",
    )
    parser.add_argument(
        "--string-mode",
        choices=("mixed", "xor", "b85", "reverse", "split"),
        default="mixed",
        help="String obfuscation style",
    )
    parser.add_argument("--flow-rate", type=float, default=1.0, help="0.0-1.0 chance to inject per function")
    parser.add_argument("--attr-rate", type=float, default=1.0, help="0.0-1.0 chance to rewrite each attribute load")
    parser.add_argument("--setattr-rate", type=float, default=1.0, help="0.0-1.0 chance to rewrite attribute writes/deletes")
    parser.add_argument("--call-rate", type=float, default=1.0, help="0.0-1.0 chance to rewrite each function call")
    parser.add_argument("--builtin-rate", type=float, default=1.0, help="0.0-1.0 chance to replace each builtin reference")
    parser.add_argument("--flow-count", type=int, default=1, help="Max dead blocks per function per pass")
    parser.add_argument("--string-chunk-min", type=int, default=1, help="Minimum string chunk size")
    parser.add_argument("--string-chunk-max", type=int, default=6, help="Maximum string chunk size")
    parser.add_argument(
        "--order",
        default="attrs,setattrs,calls,bools,ints,floats,bytes,none,flow",
        help="Comma-separated per-pass transform order",
    )
    parser.add_argument(
        "--dynamic-allow",
        default="",
        help="Comma-separated dynamic method allow overrides (e.g. attr:globals_getattr,call:builtins_eval_call)",
    )
    parser.add_argument(
        "--dynamic-deny",
        default="",
        help="Comma-separated dynamic method deny overrides",
    )

    parser.add_argument("--rename", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--strings", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--ints", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--floats", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--bytes", dest="bytes_", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--none", dest="none_values", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--bools", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--flow", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--attrs", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--setattrs", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--calls", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--builtins", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--wrap", action=argparse.BooleanOptionalAction, default=None)

    parser.add_argument(
        "--preserve",
        default="",
        help="Comma-separated names to never rename (e.g. main,api_key)",
    )
    parser.add_argument(
        "--preserve-attrs",
        default="",
        help="Comma-separated attribute names to avoid getattr-rewrite",
    )
    parser.add_argument("--keep-docstrings", action="store_true", help="Keep docstrings intact")
    parser.add_argument("--seed", type=int, default=None, help="Deterministic random seed")
    parser.add_argument("--emit-map", type=Path, default=None, help="Write rename map as JSON")
    parser.add_argument("--emit-meta", type=Path, default=None, help="Write obfumeta JSON metadata")
    parser.add_argument(
        "--meta-include-source",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Include compressed original source in metadata for lossless deobfuscation",
    )
    parser.add_argument(
        "--deobf-mode",
        choices=("best-effort", "strict"),
        default="best-effort",
        help="Behavior when source payload is absent in metadata",
    )
    parser.add_argument("--deobfuscate", action="store_true", help="Deobfuscate using obfumeta")
    parser.add_argument("--meta", type=Path, default=None, help="Path to obfumeta JSON for deobfuscation")
    parser.add_argument("--force", action="store_true", help="Ignore hash mismatches during deobfuscation")
    parser.add_argument("--check", action="store_true", help="Compile output after generation")
    parser.add_argument("--explain", action="store_true", help="Print resolved config details")

    return parser.parse_args()


def default_features(level: int) -> dict[str, int | bool]:
    presets: dict[int, dict[str, int | bool]] = {
        1: {
            "rename": True,
            "strings": False,
            "ints": False,
            "floats": False,
            "bytes_": False,
            "none_values": False,
            "bools": False,
            "flow": False,
            "attrs": False,
            "setattrs": False,
            "calls": False,
            "builtins": False,
            "wrap": False,
            "passes": 1,
            "junk": 0,
        },
        2: {
            "rename": True,
            "strings": True,
            "ints": False,
            "floats": False,
            "bytes_": False,
            "none_values": False,
            "bools": False,
            "flow": False,
            "attrs": False,
            "setattrs": False,
            "calls": False,
            "builtins": True,
            "wrap": False,
            "passes": 1,
            "junk": 0,
        },
        3: {
            "rename": True,
            "strings": True,
            "ints": True,
            "floats": True,
            "bytes_": False,
            "none_values": True,
            "bools": False,
            "flow": True,
            "attrs": False,
            "setattrs": True,
            "calls": False,
            "builtins": True,
            "wrap": False,
            "passes": 1,
            "junk": 0,
        },
        4: {
            "rename": True,
            "strings": True,
            "ints": True,
            "floats": True,
            "bytes_": True,
            "none_values": True,
            "bools": True,
            "flow": True,
            "attrs": True,
            "setattrs": True,
            "calls": True,
            "builtins": True,
            "wrap": False,
            "passes": 2,
            "junk": 1,
        },
        5: {
            "rename": True,
            "strings": True,
            "ints": True,
            "floats": True,
            "bytes_": True,
            "none_values": True,
            "bools": True,
            "flow": True,
            "attrs": True,
            "setattrs": True,
            "calls": True,
            "builtins": True,
            "wrap": True,
            "passes": 2,
            "junk": 3,
        },
    }
    return presets[level]


def profile_defaults(profile: str) -> dict[str, int | bool | float | str]:
    profiles: dict[str, dict[str, int | bool | float | str]] = {
        "balanced": {
            "rename": True,
            "strings": True,
            "ints": True,
            "floats": True,
            "bytes_": True,
            "none_values": True,
            "bools": True,
            "flow": True,
            "attrs": True,
            "setattrs": True,
            "calls": True,
            "builtins": True,
            "passes": 2,
            "junk": 1,
            "wrap": False,
            "dynamic_level": "medium",
            "attr_rate": 0.75,
            "setattr_rate": 0.8,
            "call_rate": 0.65,
            "builtin_rate": 0.9,
            "flow_rate": 0.75,
            "flow_count": 1,
        },
        "stealth": {
            "rename": True,
            "strings": True,
            "ints": True,
            "floats": True,
            "bytes_": False,
            "none_values": True,
            "bools": True,
            "flow": True,
            "attrs": True,
            "setattrs": True,
            "calls": True,
            "builtins": True,
            "passes": 1,
            "junk": 0,
            "wrap": False,
            "dynamic_level": "safe",
            "attr_rate": 0.45,
            "setattr_rate": 0.45,
            "call_rate": 0.4,
            "builtin_rate": 0.6,
            "flow_rate": 0.35,
            "flow_count": 1,
        },
        "max": {
            "rename": True,
            "strings": True,
            "ints": True,
            "floats": True,
            "bytes_": True,
            "none_values": True,
            "bools": True,
            "flow": True,
            "attrs": True,
            "setattrs": True,
            "calls": True,
            "builtins": True,
            "passes": 3,
            "junk": 4,
            "wrap": True,
            "dynamic_level": "heavy",
            "attr_rate": 1.0,
            "setattr_rate": 1.0,
            "call_rate": 1.0,
            "builtin_rate": 1.0,
            "flow_rate": 1.0,
            "flow_count": 2,
        },
    }
    return profiles[profile]


def parse_dynamic_tokens(raw: str) -> list[tuple[str | None, str]]:
    tokens = [part.strip() for part in raw.split(",") if part.strip()]
    parsed: list[tuple[str | None, str]] = []
    for token in tokens:
        if ":" in token:
            family, method = token.split(":", 1)
            parsed.append((family.strip(), method.strip()))
        else:
            parsed.append((None, token))
    return parsed


def apply_dynamic_overrides(
    methods: dict[str, set[str]],
    allow_tokens: list[tuple[str | None, str]],
    deny_tokens: list[tuple[str | None, str]],
) -> set[tuple[str, str]]:
    def _resolve_targets(family: str | None, method: str) -> list[str]:
        if family is not None:
            if family not in AVAILABLE_METHODS:
                raise ValueError(f"Unknown dynamic method family: {family}")
            if method not in AVAILABLE_METHODS[family]:
                raise ValueError(f"Unknown dynamic method {family}:{method}")
            return [family]
        targets = [fam for fam, names in AVAILABLE_METHODS.items() if method in names]
        if not targets:
            raise ValueError(f"Unknown dynamic method: {method}")
        return targets

    explicit_allow: set[tuple[str, str]] = set()
    for family, method in allow_tokens:
        for fam in _resolve_targets(family, method):
            methods[fam].add(method)
            explicit_allow.add((fam, method))
    for family, method in deny_tokens:
        for fam in _resolve_targets(family, method):
            methods[fam].discard(method)
    return explicit_allow


def sanitize_dynamic_methods(methods: dict[str, set[str]]) -> dict[str, tuple[str, ...]]:
    out: dict[str, tuple[str, ...]] = {}
    for family in METHOD_FAMILIES:
        names = [name for name in AVAILABLE_METHODS[family] if name in methods[family]]
        if not names:
            names = [AVAILABLE_METHODS[family][0]]
        out[family] = tuple(names)
    return out


def apply_explicit_method_mode(config_methods: dict[str, set[str]], args: argparse.Namespace) -> None:
    attr_map = {
        "getattr": ("getattr",),
        "builtins": ("builtins_getattr",),
        "attrgetter": ("operator_attrgetter",),
        "lambda": ("lambda_getattr",),
    }
    if args.attr_mode in attr_map:
        config_methods["attr"] = set(attr_map[args.attr_mode])

    setattr_map = {
        "setattr": ("setattr", "delattr"),
        "builtins": ("builtins_setattr", "builtins_delattr"),
        "lambda": ("lambda_setattr", "lambda_delattr"),
    }
    if args.setattr_mode in setattr_map:
        config_methods["setattr"] = set(setattr_map[args.setattr_mode])

    call_map = {
        "wrap": ("helper_wrap",),
        "lambda": ("lambda_wrap",),
        "eval": ("builtins_eval_call",),
    }
    if args.call_mode in call_map:
        config_methods["call"] = set(call_map[args.call_mode])

    builtin_map = {
        "alias": ("alias",),
        "getattr": ("builtins_getattr_alias",),
        "globals": ("globals_lookup",),
    }
    if args.builtin_mode in builtin_map:
        config_methods["builtin"] = set(builtin_map[args.builtin_mode])


def parse_transform_order(raw: str) -> tuple[str, ...]:
    parsed = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not parsed:
        return PASS_TRANSFORMS
    if len(set(parsed)) != len(parsed):
        raise ValueError("Duplicate transform in --order")
    invalid = [part for part in parsed if part not in PASS_TRANSFORMS]
    if invalid:
        raise ValueError(f"Unknown transform(s) in --order: {', '.join(invalid)}")
    return parsed


def resolve_config(args: argparse.Namespace) -> ObfuscationConfig:
    base = default_features(args.level)
    prof = profile_defaults(args.profile)

    passes_default = int(prof.get("passes", base["passes"]))
    junk_default = int(prof.get("junk", base["junk"]))
    wrap_default = bool(prof.get("wrap", base["wrap"]))

    passes = passes_default if args.passes <= 0 else args.passes
    junk = junk_default if args.junk < 0 else args.junk

    rename = bool(prof.get("rename", base["rename"]) if args.rename is None else args.rename)
    strings = bool(prof.get("strings", base["strings"]) if args.strings is None else args.strings)
    ints = bool(prof.get("ints", base["ints"]) if args.ints is None else args.ints)
    floats = bool(prof.get("floats", base["floats"]) if args.floats is None else args.floats)
    bytes_ = bool(prof.get("bytes_", base["bytes_"]) if args.bytes_ is None else args.bytes_)
    none_values = bool(
        prof.get("none_values", base["none_values"]) if args.none_values is None else args.none_values
    )
    bools = bool(prof.get("bools", base["bools"]) if args.bools is None else args.bools)
    flow = bool(prof.get("flow", base["flow"]) if args.flow is None else args.flow)
    attrs = bool(prof.get("attrs", base["attrs"]) if args.attrs is None else args.attrs)
    setattrs = bool(prof.get("setattrs", base["setattrs"]) if args.setattrs is None else args.setattrs)
    calls = bool(prof.get("calls", base["calls"]) if args.calls is None else args.calls)
    builtins_rename = bool(
        prof.get("builtins", base["builtins"]) if args.builtins is None else args.builtins
    )
    wrap = bool(wrap_default if args.wrap is None else args.wrap)

    preserve_names = {name.strip() for name in args.preserve.split(",") if name.strip()}
    preserve_names.update({"__name__", "__file__", "__package__", "__spec__"})

    preserve_attrs = {name.strip() for name in args.preserve_attrs.split(",") if name.strip()}
    preserve_attrs.update(
        {
            "format",
            "append",
            "extend",
            "items",
            "keys",
            "values",
            "read",
            "write",
            "close",
        }
    )

    default_dynamic_level = str(prof.get("dynamic_level", args.dynamic_level))
    dynamic_level = default_dynamic_level

    attr_rate = float(prof.get("attr_rate", args.attr_rate))
    setattr_rate = float(prof.get("setattr_rate", args.setattr_rate))
    call_rate = float(prof.get("call_rate", args.call_rate))
    builtin_rate = float(prof.get("builtin_rate", args.builtin_rate))
    flow_rate = float(prof.get("flow_rate", args.flow_rate))
    flow_count_default = int(prof.get("flow_count", args.flow_count))
    flow_count = flow_count_default

    # Explicit numeric CLI flags override profile defaults.
    if "--attr-rate" in sys.argv:
        attr_rate = args.attr_rate
    if "--setattr-rate" in sys.argv:
        setattr_rate = args.setattr_rate
    if "--call-rate" in sys.argv:
        call_rate = args.call_rate
    if "--builtin-rate" in sys.argv:
        builtin_rate = args.builtin_rate
    if "--flow-rate" in sys.argv:
        flow_rate = args.flow_rate
    if "--flow-count" in sys.argv:
        flow_count = args.flow_count
    if "--dynamic-level" in sys.argv:
        dynamic_level = args.dynamic_level

    if flow_rate < 0.0 or flow_rate > 1.0:
        raise ValueError("--flow-rate must be between 0.0 and 1.0")
    if attr_rate < 0.0 or attr_rate > 1.0:
        raise ValueError("--attr-rate must be between 0.0 and 1.0")
    if setattr_rate < 0.0 or setattr_rate > 1.0:
        raise ValueError("--setattr-rate must be between 0.0 and 1.0")
    if call_rate < 0.0 or call_rate > 1.0:
        raise ValueError("--call-rate must be between 0.0 and 1.0")
    if builtin_rate < 0.0 or builtin_rate > 1.0:
        raise ValueError("--builtin-rate must be between 0.0 and 1.0")
    if flow_count <= 0:
        raise ValueError("--flow-count must be >= 1")
    if args.string_chunk_min <= 0 or args.string_chunk_max <= 0:
        raise ValueError("--string chunk sizes must be >= 1")
    if args.string_chunk_min > args.string_chunk_max:
        raise ValueError("--string-chunk-min must be <= --string-chunk-max")
    if args.deobfuscate and args.meta is None:
        raise ValueError("--meta is required with --deobfuscate")

    transform_order = parse_transform_order(args.order)

    if dynamic_level not in DYNAMIC_LEVEL_DEFAULTS:
        raise ValueError(f"Unknown dynamic level: {dynamic_level}")

    dynamic_methods: dict[str, set[str]] = {
        family: set(DYNAMIC_LEVEL_DEFAULTS[dynamic_level][family]) for family in METHOD_FAMILIES
    }
    allow_tokens = parse_dynamic_tokens(args.dynamic_allow)
    deny_tokens = parse_dynamic_tokens(args.dynamic_deny)
    explicit_allow = apply_dynamic_overrides(dynamic_methods, allow_tokens, deny_tokens)
    # Risky methods are opt-in only through explicit allow tokens.
    for family, risky in RISKY_METHODS.items():
        for method in list(dynamic_methods[family]):
            if method in risky and (family, method) not in explicit_allow:
                dynamic_methods[family].discard(method)
    apply_explicit_method_mode(dynamic_methods, args)
    resolved_dynamic_methods = sanitize_dynamic_methods(dynamic_methods)

    return ObfuscationConfig(
        level=args.level,
        profile=args.profile,
        dynamic_level=dynamic_level,
        deobf_mode=args.deobf_mode,
        passes=max(1, passes),
        rename=rename,
        strings=strings,
        ints=ints,
        floats=floats,
        bytes_=bytes_,
        none_values=none_values,
        bools=bools,
        flow=flow,
        attrs=attrs,
        setattrs=setattrs,
        calls=calls,
        builtins=builtins_rename,
        wrap=wrap,
        junk=max(0, junk),
        junk_position=args.junk_position,
        string_mode=args.string_mode,
        int_mode=args.int_mode,
        float_mode=args.float_mode,
        bytes_mode=args.bytes_mode,
        bool_mode=args.bool_mode,
        none_mode=args.none_mode,
        call_mode=args.call_mode,
        setattr_mode=args.setattr_mode,
        builtin_mode=args.builtin_mode,
        attr_mode=args.attr_mode,
        flow_rate=flow_rate,
        attr_rate=attr_rate,
        setattr_rate=setattr_rate,
        call_rate=call_rate,
        builtin_rate=builtin_rate,
        flow_count=flow_count,
        string_chunk_min=args.string_chunk_min,
        string_chunk_max=args.string_chunk_max,
        transform_order=transform_order,
        keep_docstrings=args.keep_docstrings,
        preserve_names=preserve_names,
        preserve_attrs=preserve_attrs,
        seed=args.seed,
        emit_map=args.emit_map,
        emit_meta=args.emit_meta,
        meta_include_source=args.meta_include_source,
        dynamic_methods=resolved_dynamic_methods,
        check=args.check,
        explain=args.explain,
    )


def collect_identifiers(tree: ast.AST) -> set[str]:
    ids: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            ids.add(node.id)
        elif isinstance(node, ast.FunctionDef):
            ids.add(node.name)
        elif isinstance(node, ast.AsyncFunctionDef):
            ids.add(node.name)
        elif isinstance(node, ast.ClassDef):
            ids.add(node.name)
        elif isinstance(node, ast.arg):
            ids.add(node.arg)
    return ids


def collect_bound_identifiers(tree: ast.AST) -> set[str]:
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and isinstance(node.name, str):
            bound.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    bound.add(alias.asname or alias.name)
    return bound


def collect_builtin_loads(tree: ast.AST, preserve_names: set[str]) -> list[str]:
    bound_names = collect_bound_identifiers(tree) | preserve_names
    found: set[str] = set()

    class BuiltinLoadVisitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:
            if (
                isinstance(node.ctx, ast.Load)
                and node.id in BUILTIN_NAMES
                and node.id not in bound_names
                and not (node.id.startswith("__") and node.id.endswith("__"))
            ):
                found.add(node.id)

    BuiltinLoadVisitor().visit(tree)
    return sorted(found)


def build_string_helper(name: str) -> ast.FunctionDef:
    helper_source = (
        f"def {name}(mode, payload):\n"
        "    if mode == 0:\n"
        "        return \"\".join(\"\".join(chr(c ^ key) for c in data) for key, data in payload)\n"
        "    if mode == 1:\n"
        "        import base64\n"
        "        return base64.b85decode(payload.encode(\"ascii\")).decode(\"utf-8\")\n"
        "    return payload[::-1]\n"
    )
    module = ast.parse(helper_source)
    fn = module.body[0]
    assert isinstance(fn, ast.FunctionDef)
    return fn


def build_call_helper(name: str) -> ast.FunctionDef:
    helper_source = (
        f"def {name}(fn, args, kwargs):\n"
        "    return fn(*args, **kwargs)\n"
    )
    module = ast.parse(helper_source)
    fn = module.body[0]
    assert isinstance(fn, ast.FunctionDef)
    return fn


def build_builtin_alias(alias_name: str, builtin_name: str, mode: str) -> ast.Assign:
    if mode == "builtins_getattr_alias":
        value: ast.expr = ast.Call(
            func=ast.Name(id="getattr", ctx=ast.Load()),
            args=[
                ast.Call(
                    func=ast.Name(id="__import__", ctx=ast.Load()),
                    args=[ast.Constant("builtins")],
                    keywords=[],
                ),
                ast.Constant(builtin_name),
            ],
            keywords=[],
        )
    elif mode == "globals_lookup":
        value = ast.Call(
            func=ast.Attribute(
                value=ast.Call(func=ast.Name(id="globals", ctx=ast.Load()), args=[], keywords=[]),
                attr="get",
                ctx=ast.Load(),
            ),
            args=[ast.Constant(builtin_name), ast.Name(id=builtin_name, ctx=ast.Load())],
            keywords=[],
        )
    else:
        value = ast.Name(id=builtin_name, ctx=ast.Load())
    return ast.Assign(targets=[ast.Name(id=alias_name, ctx=ast.Store())], value=value)


def insert_after_docstring(module: ast.Module, stmt: ast.stmt) -> None:
    if (
        module.body
        and isinstance(module.body[0], ast.Expr)
        and isinstance(module.body[0].value, ast.Constant)
        and isinstance(module.body[0].value.value, str)
    ):
        module.body.insert(1, stmt)
    else:
        module.body.insert(0, stmt)


def build_junk_function(name: str, rng: random.Random) -> ast.FunctionDef:
    seed = rng.randint(100, 9999)
    body_src = (
        f"def {name}(x={seed}):\n"
        "    y = ((x ^ 1337) + 97) - 97\n"
        "    if y == -1:\n"
        "        return y\n"
        "    return y ^ 0\n"
    )
    module = ast.parse(body_src)
    fn = module.body[0]
    assert isinstance(fn, ast.FunctionDef)
    return fn


def docstring_insert_index(body: list[ast.stmt]) -> int:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return 1
    return 0


def inject_junk_functions(tree: ast.AST, rng: random.Random, count: int, position: str) -> int:
    if count <= 0 or not isinstance(tree, ast.Module):
        return 0

    used = collect_identifiers(tree)
    inserted = 0
    for idx in range(count):
        base = f"_junk_{idx:x}"
        name = base
        suffix = 0
        while name in used:
            suffix += 1
            name = f"{base}_{suffix:x}"
        used.add(name)
        stmt = build_junk_function(name, rng)
        if position == "bottom":
            tree.body.append(stmt)
        elif position == "random":
            start = docstring_insert_index(tree.body)
            idx = rng.randint(start, len(tree.body))
            tree.body.insert(idx, stmt)
        else:
            insert_after_docstring(tree, stmt)
        inserted += 1

    return inserted


def preserve_shebang(source: str, output: str) -> str:
    lines = source.splitlines()
    if lines and lines[0].startswith("#!"):
        return lines[0] + "\n" + output
    return output


def wrap_source(source: str) -> str:
    code = compile(source, "<obfuscated>", "exec")
    payload = base64.b85encode(zlib.compress(marshal.dumps(code), 9)).decode("ascii")
    return (
        "import base64 as _b, zlib as _z, marshal as _m\n"
        f"exec(_m.loads(_z.decompress(_b.b85decode({payload!r}))))"
    )


def obfuscate_source(
    source: str,
    config: ObfuscationConfig,
) -> tuple[str, dict[str, str], ObfuscationStats]:
    tree = ast.parse(source)
    rng = random.Random(config.seed)
    stats = ObfuscationStats()
    if "builtins_eval_call" in config.dynamic_methods["call"]:
        stats.warnings.append("risky method enabled: call:builtins_eval_call")

    stats.junk_functions = inject_junk_functions(tree, rng, config.junk, config.junk_position)

    rename_map: dict[str, str] = {}
    if config.rename:
        used = collect_identifiers(tree) | config.preserve_names
        generator = NameGenerator(used)
        collector = RenameCollector(config.preserve_names, generator)
        collector.visit(tree)
        rename_map = collector.mapping
        tree = Renamer(rename_map).visit(tree)
        stats.renamed = len(rename_map)

    if config.strings:
        helper_name = "_obf_str"
        while helper_name in collect_identifiers(tree):
            helper_name += "_x"
        string_obf = StringObfuscator(
            helper_name,
            rng,
            config.keep_docstrings,
            config.string_chunk_min,
            config.string_chunk_max,
            config.string_mode,
        )
        tree = string_obf.visit(tree)
        stats.strings += string_obf.changed
        if string_obf.changed > 0 and isinstance(tree, ast.Module):
            insert_after_docstring(tree, build_string_helper(helper_name))

    call_helper_name = "_obf_call"
    if config.calls and (
        (config.call_mode in {"mixed", "wrap"} and "helper_wrap" in config.dynamic_methods["call"])
        or config.call_mode == "wrap"
    ):
        while call_helper_name in collect_identifiers(tree):
            call_helper_name += "_x"

    for _ in range(config.passes):
        for transform in config.transform_order:
            if transform == "attrs" and config.attrs:
                attr_obf = AttributeLoadObfuscator(
                    rng,
                    config.preserve_attrs,
                    config.attr_mode,
                    config.attr_rate,
                    config.dynamic_methods["attr"],
                )
                tree = attr_obf.visit(tree)
                stats.attrs += attr_obf.changed
            elif transform == "setattrs" and config.setattrs:
                setattrs_obf = SetAttrRewriter(
                    rng,
                    config.preserve_attrs,
                    config.setattr_mode,
                    config.setattr_rate,
                    config.dynamic_methods["setattr"],
                )
                tree = setattrs_obf.visit(tree)
                stats.setattrs += setattrs_obf.changed
            elif transform == "calls" and config.calls:
                call_obf = CallObfuscator(
                    rng,
                    call_helper_name,
                    config.call_mode,
                    config.call_rate,
                    config.dynamic_methods["call"],
                )
                tree = call_obf.visit(tree)
                stats.calls += call_obf.changed
            elif transform == "bools" and config.bools:
                bool_obf = BoolObfuscator(rng, config.bool_mode)
                tree = bool_obf.visit(tree)
                stats.bools += bool_obf.changed
            elif transform == "ints" and config.ints:
                int_obf = IntObfuscator(rng, config.int_mode)
                tree = int_obf.visit(tree)
                stats.ints += int_obf.changed
            elif transform == "floats" and config.floats:
                float_obf = FloatObfuscator(rng, config.float_mode)
                tree = float_obf.visit(tree)
                stats.floats += float_obf.changed
            elif transform == "bytes" and config.bytes_:
                bytes_obf = BytesObfuscator(rng, config.bytes_mode)
                tree = bytes_obf.visit(tree)
                stats.bytes_ += bytes_obf.changed
            elif transform == "none" and config.none_values:
                none_obf = NoneObfuscator(rng, config.none_mode)
                tree = none_obf.visit(tree)
                stats.none_values += none_obf.changed
            elif transform == "flow" and config.flow:
                flow_obf = FlowObfuscator(
                    rng,
                    config.keep_docstrings,
                    config.flow_rate,
                    config.flow_count,
                )
                tree = flow_obf.visit(tree)
                stats.flow_blocks += flow_obf.changed

    if (
        config.calls
        and (
            (config.call_mode in {"mixed", "wrap"} and "helper_wrap" in config.dynamic_methods["call"])
            or config.call_mode == "wrap"
        )
        and stats.calls > 0
        and isinstance(tree, ast.Module)
    ):
        insert_after_docstring(tree, build_call_helper(call_helper_name))

    if config.builtins:
        builtin_targets = collect_builtin_loads(tree, config.preserve_names)
        if builtin_targets:
            used = collect_identifiers(tree) | config.preserve_names
            generator = NameGenerator(used)
            builtin_map = {name: generator.next_name() for name in builtin_targets}
            builtin_transform = BuiltinAliasTransformer(builtin_map, config.builtin_rate, rng)
            tree = builtin_transform.visit(tree)
            if isinstance(tree, ast.Module):
                for name in reversed(builtin_targets):
                    chosen = rng.choice(config.dynamic_methods["builtin"])
                    insert_after_docstring(
                        tree,
                        build_builtin_alias(builtin_map[name], name, chosen),
                    )
            stats.builtins = builtin_transform.changed

    ast.fix_missing_locations(tree)
    output = ast.unparse(tree)

    if config.wrap:
        output = wrap_source(output)

    output = preserve_shebang(source, output)

    if config.check:
        compile(output, "<obfuscated>", "exec")

    return output, rename_map, stats


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def encode_source_payload(source: str) -> str:
    return base64.b85encode(zlib.compress(source.encode("utf-8"), 9)).decode("ascii")


def decode_source_payload(payload: str) -> str:
    return zlib.decompress(base64.b85decode(payload.encode("ascii"))).decode("utf-8")


def config_to_meta(config: ObfuscationConfig) -> dict[str, object]:
    return {
        "profile": config.profile,
        "dynamic_level": config.dynamic_level,
        "deobf_mode": config.deobf_mode,
        "level": config.level,
        "passes": config.passes,
        "flags": {
            "rename": config.rename,
            "strings": config.strings,
            "ints": config.ints,
            "floats": config.floats,
            "bytes": config.bytes_,
            "none": config.none_values,
            "bools": config.bools,
            "flow": config.flow,
            "attrs": config.attrs,
            "setattrs": config.setattrs,
            "calls": config.calls,
            "builtins": config.builtins,
            "wrap": config.wrap,
        },
        "rates": {
            "attr_rate": config.attr_rate,
            "setattr_rate": config.setattr_rate,
            "call_rate": config.call_rate,
            "builtin_rate": config.builtin_rate,
            "flow_rate": config.flow_rate,
        },
        "dynamic_methods": {k: list(v) for k, v in config.dynamic_methods.items()},
        "junk": {"count": config.junk, "position": config.junk_position},
        "string": {
            "mode": config.string_mode,
            "chunk_min": config.string_chunk_min,
            "chunk_max": config.string_chunk_max,
        },
        "int_mode": config.int_mode,
        "float_mode": config.float_mode,
        "bytes_mode": config.bytes_mode,
        "bool_mode": config.bool_mode,
        "none_mode": config.none_mode,
        "call_mode": config.call_mode,
        "setattr_mode": config.setattr_mode,
        "builtin_mode": config.builtin_mode,
        "attr_mode": config.attr_mode,
        "attr_rate": config.attr_rate,
        "flow_rate": config.flow_rate,
        "flow_count": config.flow_count,
        "order": list(config.transform_order),
        "seed": config.seed,
    }


def stats_to_meta(stats: ObfuscationStats) -> dict[str, int]:
    return {
        "renamed": stats.renamed,
        "strings": stats.strings,
        "ints": stats.ints,
        "floats": stats.floats,
        "bytes": stats.bytes_,
        "none": stats.none_values,
        "bools": stats.bools,
        "flow_blocks": stats.flow_blocks,
        "attrs": stats.attrs,
        "setattrs": stats.setattrs,
        "calls": stats.calls,
        "builtins": stats.builtins,
        "junk_functions": stats.junk_functions,
    }


def build_obfumeta(
    config: ObfuscationConfig,
    source: str,
    output: str,
    rename_map: dict[str, str],
    stats: ObfuscationStats,
) -> dict[str, object]:
    meta: dict[str, object] = {
        "format": "obfumeta-v2",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "config": config_to_meta(config),
        "stats": stats_to_meta(stats),
        "rename_map": rename_map,
        "input_sha256": sha256_text(source),
        "output_sha256": sha256_text(output),
        "warnings": list(stats.warnings),
    }
    if config.meta_include_source:
        meta["original_source_b85_zlib"] = encode_source_payload(source)
    return meta


def write_obfumeta(path: Path, meta: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")


def deobfuscate_with_meta(
    obfuscated_source: str,
    meta_path: Path,
    mode: str,
    force: bool = False,
) -> tuple[str, list[str]]:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("format") not in {"obfumeta-v1", "obfumeta-v2"}:
        raise ValueError("Unsupported metadata format")

    warnings: list[str] = []
    expected_hash = meta.get("output_sha256")
    if isinstance(expected_hash, str):
        actual = sha256_text(obfuscated_source)
        if actual != expected_hash and not force:
            raise ValueError("Output hash mismatch (use --force to ignore)")
        if actual != expected_hash and force:
            warnings.append("hash mismatch ignored due to --force")

    payload = meta.get("original_source_b85_zlib")
    if isinstance(payload, str):
        return decode_source_payload(payload), warnings

    raw_map = meta.get("rename_map")
    if isinstance(raw_map, dict):
        reverse_map = {str(v): str(k) for k, v in raw_map.items()}
        tree = ast.parse(obfuscated_source)
        restored = Renamer(reverse_map).visit(tree)
        ast.fix_missing_locations(restored)
        warnings.append("best-effort restore: applied rename map only; other transforms may remain")
        if mode == "strict":
            raise ValueError("Strict mode requires source payload in metadata")
        return ast.unparse(restored), warnings

    if mode == "strict":
        raise ValueError("Strict mode requires source payload in metadata")
    warnings.append("best-effort restore unavailable: returning obfuscated source")
    return obfuscated_source, warnings


def explain_config(config: ObfuscationConfig) -> None:
    print(
        "Config: "
        f"level={config.level}, profile={config.profile}, dynamic={config.dynamic_level}, "
        f"passes={config.passes}, order={','.join(config.transform_order)}, "
        f"junk={config.junk}@{config.junk_position}, str_mode={config.string_mode}, "
        f"int_mode={config.int_mode}, float_mode={config.float_mode}, "
        f"bytes_mode={config.bytes_mode}, bool_mode={config.bool_mode}, none_mode={config.none_mode}, "
        f"call_mode={config.call_mode}, setattr_mode={config.setattr_mode}, builtin_mode={config.builtin_mode}, "
        f"attr_mode={config.attr_mode}, attr_rate={config.attr_rate:.2f}, "
        f"setattr_rate={config.setattr_rate:.2f}, call_rate={config.call_rate:.2f}, "
        f"builtin_rate={config.builtin_rate:.2f}, flow_rate={config.flow_rate:.2f}, flow_count={config.flow_count}, "
        f"str_chunks={config.string_chunk_min}-{config.string_chunk_max}"
    )
    print(
        "Dynamic methods: "
        + ", ".join(f"{k}=[{','.join(v)}]" for k, v in config.dynamic_methods.items())
    )


def main() -> int:
    args = parse_args()
    try:
        config = resolve_config(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    source = args.input.read_text(encoding="utf-8")
    if args.deobfuscate:
        if args.meta is None:
            print("error: --meta is required with --deobfuscate", file=sys.stderr)
            return 2
        try:
            restored, deobf_warnings = deobfuscate_with_meta(
                source,
                args.meta,
                config.deobf_mode,
                args.force,
            )
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(restored + "\n", encoding="utf-8")
        print(f"Deobfuscated: {args.output} using meta={args.meta}")
        for warn in deobf_warnings:
            print(f"warning: {warn}")
        return 0

    if config.explain:
        explain_config(config)

    output, rename_map, stats = obfuscate_source(source, config)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    written_output = output + "\n"
    args.output.write_text(written_output, encoding="utf-8")

    if config.emit_map is not None:
        config.emit_map.parent.mkdir(parents=True, exist_ok=True)
        config.emit_map.write_text(
            json.dumps(rename_map, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    if config.emit_meta is not None:
        write_obfumeta(
            config.emit_meta,
            build_obfumeta(config, source, written_output, rename_map, stats),
        )

    print(
        f"Wrote: {args.output} | "
        f"features(profile={config.profile}, dynamic={config.dynamic_level}, "
        f"rename={config.rename}, strings={config.strings}, ints={config.ints}, "
        f"floats={config.floats}, bytes={config.bytes_}, none={config.none_values}, "
        f"bools={config.bools}, flow={config.flow}, attrs={config.attrs}, "
        f"setattrs={config.setattrs}, calls={config.calls}, builtins={config.builtins}, "
        f"wrap={config.wrap}, "
        f"order={','.join(config.transform_order)}) | "
        f"stats(renamed={stats.renamed}, strings={stats.strings}, ints={stats.ints}, "
        f"floats={stats.floats}, bytes={stats.bytes_}, none={stats.none_values}, "
        f"bools={stats.bools}, dead_blocks={stats.flow_blocks}, attrs={stats.attrs}, "
        f"setattrs={stats.setattrs}, calls={stats.calls}, builtins={stats.builtins}, "
        f"junk={stats.junk_functions})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
