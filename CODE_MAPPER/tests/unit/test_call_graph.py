"""Unit tests for Phase 3 call graph index."""

import os
import time

from orchestrator import call_graph as call_graph_module
from orchestrator.call_graph import CallGraphIndex


def test_call_graph_detects_cross_file_call_python(fixture_repo_multifile):
    """CallGraphIndex should detect api.py -> db.py function boundary hop."""
    code_files = sorted(fixture_repo_multifile.rglob("*.py"))
    index = CallGraphIndex(max_hops=4, max_chains_per_file=10)
    index.build(fixture_repo_multifile, code_files)

    api_file = str((fixture_repo_multifile / "api.py").resolve())
    hints = index.file_hints(api_file)

    assert hints["stats"]["functions_in_file"] >= 1
    assert hints["stats"]["direct_cross_file_call_count"] >= 1
    assert any(
        call["to_file"].endswith("db.py") and call["to_function"] == "execute_query"
        for call in hints["direct_cross_file_calls"]
    )


def test_call_graph_cache_invalidates_changed_file_symbols(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "service.py"
    target.write_text(
        "def foo(x):\n    return helper(x)\n\ndef helper(v):\n    return v\n",
        encoding="utf-8",
    )

    index = CallGraphIndex(max_hops=4, max_chains_per_file=10)
    code_files = sorted(repo.rglob("*.py"))
    index.build(repo, code_files)
    assert "foo" in index.symbols_by_name

    cache_file = repo / ".cache" / "call_graph.json"
    cache_mtime = cache_file.stat().st_mtime
    target.write_text(
        "def bar(x):\n    return helper(x)\n\ndef helper(v):\n    return v\n",
        encoding="utf-8",
    )
    os.utime(target, (cache_mtime + 2.0, cache_mtime + 2.0))
    time.sleep(0.01)

    code_files = sorted(repo.rglob("*.py"))
    index.build(repo, code_files)

    assert "foo" not in index.symbols_by_name
    assert "bar" in index.symbols_by_name
    for symbol_ids in index.symbols_by_name.values():
        assert len(symbol_ids) == len(set(symbol_ids))


def test_call_graph_cache_invalidates_deleted_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    file_a = repo / "a.py"
    file_b = repo / "b.py"
    file_a.write_text("def a():\n    return 1\n", encoding="utf-8")
    file_b.write_text("def b():\n    return 2\n", encoding="utf-8")

    index = CallGraphIndex(max_hops=4, max_chains_per_file=10)
    code_files = sorted(repo.rglob("*.py"))
    index.build(repo, code_files)
    deleted_path = str(file_b.resolve())
    assert deleted_path in index.symbols_by_file

    file_b.unlink()
    cache_file = repo / ".cache" / "call_graph.json"
    os.utime(file_a, (cache_file.stat().st_mtime + 2.0, cache_file.stat().st_mtime + 2.0))

    code_files = sorted(repo.rglob("*.py"))
    index.build(repo, code_files)

    assert all(symbol.file != deleted_path for symbol in index.symbols_by_id.values())
    assert deleted_path not in index.symbols_by_file


def test_js_ts_index_passes_suffix_to_treesitter_parser(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    ts_file = repo / "module.ts"
    ts_file.write_text("export function run(x) { return x; }\n", encoding="utf-8")
    seen_suffixes: list[str] = []

    def fake_treesitter(file: str, source: str, suffix: str):
        seen_suffixes.append(suffix)
        return []

    monkeypatch.setattr(call_graph_module, "_parse_js_ts_treesitter", fake_treesitter)
    monkeypatch.setattr(call_graph_module, "_parse_js_ts_symbols", lambda file, source: [])

    index = CallGraphIndex(max_hops=2, max_chains_per_file=5)
    index._index_js_ts_file(ts_file)

    assert seen_suffixes == [".ts"]
