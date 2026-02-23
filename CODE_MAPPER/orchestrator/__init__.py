"""Orchestrator package exports with lazy loading."""

__all__ = [
    "AnalysisResult",
    "CallGraphIndex",
    "RepoScanResult",
    "RepoScanner",
    "TaintAnalystOrchestrator",
]


def __getattr__(name):
    if name == "CallGraphIndex":
        from .call_graph import CallGraphIndex

        return CallGraphIndex
    if name in {"AnalysisResult", "TaintAnalystOrchestrator"}:
        from .control_plane import AnalysisResult, TaintAnalystOrchestrator

        return {"AnalysisResult": AnalysisResult, "TaintAnalystOrchestrator": TaintAnalystOrchestrator}[name]
    if name in {"RepoScanResult", "RepoScanner"}:
        from .repo_scanner import RepoScanResult, RepoScanner

        return {"RepoScanResult": RepoScanResult, "RepoScanner": RepoScanner}[name]
    raise AttributeError(name)
