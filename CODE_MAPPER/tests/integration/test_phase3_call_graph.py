"""Phase 3 integration sanity checks."""

from orchestrator.call_graph import CallGraphIndex


def test_phase3_call_graph_multifile_fixture(fixture_repo_multifile):
    """Phase 3 call graph should resolve cross-file chain for multifile Python fixture."""
    code_files = sorted(fixture_repo_multifile.rglob("*.py"))
    graph = CallGraphIndex(max_hops=5, max_chains_per_file=20)
    graph.build(fixture_repo_multifile, code_files)

    summary = graph.summary()
    assert summary["function_symbols"] >= 2
    assert summary["cross_file_edges"] >= 1

    hints = graph.file_hints(str((fixture_repo_multifile / "api.py").resolve()))
    assert hints["stats"]["direct_cross_file_call_count"] >= 1
    assert hints["stats"]["cross_file_chain_count"] >= 1
