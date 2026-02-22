from __future__ import annotations

import ast
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
PYTHON_EXTENSIONS = {".py"}
MAX_EDGE_TARGETS = 3


@dataclass
class CallSite:
    function_name: str
    line: int
    args: List[str] = field(default_factory=list)


@dataclass
class FunctionSymbol:
    symbol_id: str
    file: str
    function_name: str
    line: int
    parameters: List[str]
    language: str
    calls: List[CallSite] = field(default_factory=list)


@dataclass
class CallEdge:
    caller_symbol_id: str
    callee_symbol_id: str
    call_line: int
    parameter_mapping: Dict[str, str]


@dataclass
class CallHop:
    from_file: str
    from_function: str
    to_file: str
    to_function: str
    call_line: int
    parameter_mapping: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_file": self.from_file,
            "from_function": self.from_function,
            "to_file": self.to_file,
            "to_function": self.to_function,
            "call_line": self.call_line,
            "parameter_mapping": self.parameter_mapping,
        }


@dataclass
class CallChain:
    start_file: str
    start_function: str
    terminal_file: str
    terminal_function: str
    hops: List[CallHop]
    chain_length: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_file": self.start_file,
            "start_function": self.start_function,
            "terminal_file": self.terminal_file,
            "terminal_function": self.terminal_function,
            "chain_length": self.chain_length,
            "hops": [hop.to_dict() for hop in self.hops],
        }


class CallGraphIndex:
    """
    Lightweight cross-file call graph for Phase 3.

    The index is intentionally conservative: it targets common function patterns
    in Python/JS/TS and avoids speculative linking when multiple definitions
    are highly ambiguous.
    """

    def __init__(self, max_hops: int = 5, max_chains_per_file: int = 20):
        self.max_hops = max_hops
        self.max_chains_per_file = max_chains_per_file
        self.repo_path: Optional[Path] = None

        self.symbols_by_id: Dict[str, FunctionSymbol] = {}
        self.symbols_by_name: Dict[str, List[str]] = defaultdict(list)
        self.symbols_by_file: Dict[str, List[str]] = defaultdict(list)
        self.edges_by_caller: Dict[str, List[CallEdge]] = defaultdict(list)
        self._chains_cache: Dict[tuple[str, int], List[List[CallEdge]]] = {}
        self._stats: Dict[str, int] = {
            "files_scanned": 0,
            "function_symbols": 0,
            "call_edges": 0,
            "cross_file_edges": 0,
        }

    def build(self, repo_path: Path, code_files: List[Path]) -> None:
        self.repo_path = repo_path
        self.symbols_by_id.clear()
        self.symbols_by_name.clear()
        self.symbols_by_file.clear()
        self.edges_by_caller.clear()
        self._chains_cache.clear()
        self._stats = {
            "files_scanned": 0,
            "function_symbols": 0,
            "call_edges": 0,
            "cross_file_edges": 0,
        }

        for file_path in code_files:
            suffix = file_path.suffix.lower()
            if suffix in PYTHON_EXTENSIONS:
                self._index_python_file(file_path)
            elif suffix in JS_TS_EXTENSIONS:
                self._index_js_ts_file(file_path)

        self._resolve_edges()
        self._stats["function_symbols"] = len(self.symbols_by_id)
        self._stats["call_edges"] = sum(len(edges) for edges in self.edges_by_caller.values())
        self._stats["cross_file_edges"] = sum(
            1
            for edges in self.edges_by_caller.values()
            for edge in edges
            if self.symbols_by_id[edge.caller_symbol_id].file
            != self.symbols_by_id[edge.callee_symbol_id].file
        )

        logger.info(
            "[CallGraphIndex] Built with %d symbols and %d edges (%d cross-file)",
            self._stats["function_symbols"],
            self._stats["call_edges"],
            self._stats["cross_file_edges"],
        )

    def summary(self) -> Dict[str, Any]:
        return dict(self._stats)

    def file_hints(self, file_path: str, max_hops: Optional[int] = None) -> Dict[str, Any]:
        hops_limit = max_hops if max_hops is not None else self.max_hops
        normalized_file = self._normalize_file(file_path)
        symbol_ids = self.symbols_by_file.get(normalized_file, [])

        direct_cross_file_calls: List[Dict[str, Any]] = []
        call_chains: List[CallChain] = []

        for symbol_id in symbol_ids:
            symbol = self.symbols_by_id[symbol_id]
            for edge in self.edges_by_caller.get(symbol_id, []):
                callee = self.symbols_by_id.get(edge.callee_symbol_id)
                if not callee:
                    continue
                if callee.file != symbol.file:
                    direct_cross_file_calls.append(
                        {
                            "from_function": symbol.function_name,
                            "from_file": symbol.file,
                            "to_function": callee.function_name,
                            "to_file": callee.file,
                            "call_line": edge.call_line,
                            "parameter_mapping": edge.parameter_mapping,
                        }
                    )

            chain_edges = self._resolve_chains_from_symbol(symbol_id, hops_limit, set())
            for chain in chain_edges:
                if not chain:
                    continue
                hops = [self._edge_to_hop(item) for item in chain]
                if not any(hop.from_file != hop.to_file for hop in hops):
                    continue
                terminal = self.symbols_by_id[chain[-1].callee_symbol_id]
                call_chains.append(
                    CallChain(
                        start_file=symbol.file,
                        start_function=symbol.function_name,
                        terminal_file=terminal.file,
                        terminal_function=terminal.function_name,
                        hops=hops,
                        chain_length=len(hops),
                    )
                )

        call_chains = call_chains[: self.max_chains_per_file]
        return {
            "file": normalized_file,
            "direct_cross_file_calls": direct_cross_file_calls[: self.max_chains_per_file],
            "call_chains": [chain.to_dict() for chain in call_chains],
            "stats": {
                "functions_in_file": len(symbol_ids),
                "direct_cross_file_call_count": len(direct_cross_file_calls),
                "cross_file_chain_count": len(call_chains),
            },
        }

    # ------------------------------------------------------------------
    # Internal indexing
    # ------------------------------------------------------------------

    def _index_python_file(self, file_path: Path) -> None:
        self._stats["files_scanned"] += 1
        resolved = file_path.resolve()
        try:
            text = resolved.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except Exception as exc:
            logger.debug("[CallGraphIndex] Python parse failed for %s: %s", file_path, exc)
            return

        visitor = _PythonFunctionVisitor(file=str(resolved))
        visitor.visit(tree)
        for symbol in visitor.symbols:
            self._register_symbol(symbol)

    def _index_js_ts_file(self, file_path: Path) -> None:
        self._stats["files_scanned"] += 1
        resolved = file_path.resolve()
        try:
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.debug("[CallGraphIndex] JS/TS read failed for %s: %s", file_path, exc)
            return

        symbols = _parse_js_ts_symbols(str(resolved), text)
        for symbol in symbols:
            self._register_symbol(symbol)

    def _register_symbol(self, symbol: FunctionSymbol) -> None:
        self.symbols_by_id[symbol.symbol_id] = symbol
        self.symbols_by_name[symbol.function_name].append(symbol.symbol_id)
        self.symbols_by_file[symbol.file].append(symbol.symbol_id)

    def _resolve_edges(self) -> None:
        for caller in self.symbols_by_id.values():
            for call in caller.calls:
                candidates = self._resolve_callee_candidates(caller, call)
                for callee_id in candidates:
                    callee = self.symbols_by_id.get(callee_id)
                    if callee is None:
                        continue
                    parameter_mapping = {
                        param: call.args[i]
                        for i, param in enumerate(callee.parameters)
                        if i < len(call.args)
                    }
                    edge = CallEdge(
                        caller_symbol_id=caller.symbol_id,
                        callee_symbol_id=callee_id,
                        call_line=call.line,
                        parameter_mapping=parameter_mapping,
                    )
                    self.edges_by_caller[caller.symbol_id].append(edge)

    def _resolve_callee_candidates(self, caller: FunctionSymbol, call: CallSite) -> List[str]:
        candidates = self.symbols_by_name.get(call.function_name, [])
        if not candidates:
            return []

        scored: List[tuple[int, str]] = []
        caller_path = Path(caller.file)
        for candidate_id in candidates:
            candidate = self.symbols_by_id[candidate_id]
            score = 0
            if candidate.file == caller.file:
                score += 100
            if Path(candidate.file).parent == caller_path.parent:
                score += 30
            if candidate.language == caller.language:
                score += 10
            if candidate.symbol_id == caller.symbol_id:
                score -= 20
            scored.append((score, candidate_id))

        scored.sort(key=lambda item: (-item[0], item[1]))
        top = scored[:MAX_EDGE_TARGETS]
        if not top:
            return []
        max_score = top[0][0]
        filtered = [candidate_id for score, candidate_id in top if score >= max_score - 20]
        return filtered[:MAX_EDGE_TARGETS]

    # ------------------------------------------------------------------
    # Chain resolution
    # ------------------------------------------------------------------

    def _resolve_chains_from_symbol(
        self,
        symbol_id: str,
        remaining_hops: int,
        visited: Set[str],
    ) -> List[List[CallEdge]]:
        cache_key = (symbol_id, remaining_hops)
        if cache_key in self._chains_cache:
            cached = self._chains_cache[cache_key]
            return [list(chain) for chain in cached]

        if remaining_hops <= 0:
            return [[]]

        if symbol_id in visited:
            return [[]]

        visited = set(visited)
        visited.add(symbol_id)
        outgoing = self.edges_by_caller.get(symbol_id, [])
        if not outgoing:
            return [[]]

        all_chains: List[List[CallEdge]] = []
        for edge in outgoing:
            if edge.callee_symbol_id in visited:
                all_chains.append([edge])
                continue
            sub_chains = self._resolve_chains_from_symbol(
                edge.callee_symbol_id,
                remaining_hops - 1,
                visited,
            )
            if not sub_chains:
                all_chains.append([edge])
                continue
            for sub in sub_chains:
                chain = [edge] + [item for item in sub if item is not None]
                all_chains.append(chain)

        unique: List[List[CallEdge]] = []
        seen_keys: Set[tuple[str, ...]] = set()
        for chain in all_chains:
            key = tuple(f"{item.caller_symbol_id}->{item.callee_symbol_id}@{item.call_line}" for item in chain)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            unique.append(chain)

        self._chains_cache[cache_key] = [list(chain) for chain in unique]
        return unique

    def _edge_to_hop(self, edge: CallEdge) -> CallHop:
        caller = self.symbols_by_id[edge.caller_symbol_id]
        callee = self.symbols_by_id[edge.callee_symbol_id]
        return CallHop(
            from_file=caller.file,
            from_function=caller.function_name,
            to_file=callee.file,
            to_function=callee.function_name,
            call_line=edge.call_line,
            parameter_mapping=edge.parameter_mapping,
        )

    def _normalize_file(self, file_path: str) -> str:
        path = Path(file_path)
        if not path.is_absolute() and self.repo_path:
            path = (self.repo_path / path).resolve()
        return str(path)


class _PythonFunctionVisitor(ast.NodeVisitor):
    def __init__(self, file: str):
        self.file = file
        self.symbols: List[FunctionSymbol] = []
        self._stack: List[FunctionSymbol] = []
        self._class_stack: List[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        symbol = self._create_symbol(node)
        self.symbols.append(symbol)
        self._stack.append(symbol)
        self.generic_visit(node)
        self._stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        symbol = self._create_symbol(node)
        self.symbols.append(symbol)
        self._stack.append(symbol)
        self.generic_visit(node)
        self._stack.pop()

    def visit_Call(self, node: ast.Call) -> Any:
        if self._stack:
            function_name = self._extract_call_name(node.func)
            if function_name:
                self._stack[-1].calls.append(
                    CallSite(
                        function_name=function_name,
                        line=getattr(node, "lineno", 0),
                        args=[self._render_arg(arg) for arg in getattr(node, "args", [])],
                    )
                )
        self.generic_visit(node)

    def _create_symbol(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionSymbol:
        if self._class_stack:
            function_name = f"{self._class_stack[-1]}.{node.name}"
        else:
            function_name = node.name
        symbol_id = f"{self.file}::{function_name}:{getattr(node, 'lineno', 0)}"
        parameters = [arg.arg for arg in node.args.args]
        return FunctionSymbol(
            symbol_id=symbol_id,
            file=self.file,
            function_name=function_name,
            line=getattr(node, "lineno", 0),
            parameters=parameters,
            language="python",
        )

    @staticmethod
    def _extract_call_name(func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            return func_node.attr
        return ""

    @staticmethod
    def _render_arg(arg: ast.AST) -> str:
        if isinstance(arg, ast.Name):
            return arg.id
        if isinstance(arg, ast.Attribute):
            return arg.attr
        try:
            return ast.unparse(arg)
        except Exception:
            return "expr"


def _parse_js_ts_symbols(file: str, source: str) -> List[FunctionSymbol]:
    lines = source.splitlines()
    symbols: List[FunctionSymbol] = []

    func_decl = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
    arrow_decl = re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"
    )
    named_func_expr = re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)"
    )

    i = 0
    while i < len(lines):
        line = lines[i]
        match = func_decl.match(line) or arrow_decl.match(line) or named_func_expr.match(line)
        if not match:
            i += 1
            continue

        name = match.group(1)
        params = _split_args(match.group(2))
        symbol_id = f"{file}::{name}:{i + 1}"
        symbol = FunctionSymbol(
            symbol_id=symbol_id,
            file=file,
            function_name=name,
            line=i + 1,
            parameters=params,
            language="javascript",
        )

        block_start = i
        brace_balance = line.count("{") - line.count("}")
        while brace_balance <= 0 and block_start + 1 < len(lines):
            block_start += 1
            brace_balance += lines[block_start].count("{") - lines[block_start].count("}")
            if "{" in lines[block_start]:
                break

        j = block_start
        while j + 1 < len(lines) and brace_balance > 0:
            j += 1
            current = lines[j]
            brace_balance += current.count("{") - current.count("}")
            for call in _extract_js_calls(current, j + 1):
                symbol.calls.append(call)

        symbols.append(symbol)
        i = max(j + 1, i + 1)

    return symbols


def _extract_js_calls(line: str, line_no: int) -> List[CallSite]:
    call_re = re.compile(r"(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*\(([^()]*)\)")
    ignored = {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "function",
        "typeof",
        "new",
    }
    matches: List[CallSite] = []
    for match in call_re.finditer(line):
        fn = match.group(1)
        if fn in ignored:
            continue
        args = _split_args(match.group(2))
        matches.append(CallSite(function_name=fn, line=line_no, args=args))
    return matches


def _split_args(raw: str) -> List[str]:
    parts = [item.strip() for item in raw.split(",")]
    return [item for item in parts if item]
