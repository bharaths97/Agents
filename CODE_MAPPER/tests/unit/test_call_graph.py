"""Unit tests for Phase 3 call graph index."""

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
