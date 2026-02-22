from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

from config import settings

from .semgrep_rule_indexer import RuleIndex, RuleRecord, SemgrepRuleIndexer
from .semgrep_selector import RuleSelectionResult, select_rules_for_repo

logger = logging.getLogger(__name__)


@dataclass
class SemgrepFinding:
    rule_id: str
    file: str
    line: int
    end_line: int
    severity: str
    message: str
    snippet: str
    category: str
    subcategory: List[str]
    cwe: List[str]
    owasp: List[str]
    references: List[str]
    source_rule_url: str
    technology: List[str]
    confidence: str
    likelihood: str
    impact: str
    rule_path: str
    mode: str


@dataclass
class SemgrepScanResult:
    enabled: bool
    rules_root: str
    rules_indexed: int
    rules_selected: int
    findings: List[SemgrepFinding]
    selection_rationale: Dict[str, int]
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["findings"] = [asdict(item) for item in self.findings]
        return payload

    def findings_by_file(self) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.file, []).append(asdict(finding))
        for path, items in grouped.items():
            grouped[path] = items[: settings.semgrep_max_findings_per_file]
        return grouped


class SemgrepRunner:
    def __init__(self, rules_root: Path, repo_path: Path):
        self.rules_root = rules_root
        self.repo_path = repo_path

    def run(self, scan_result) -> SemgrepScanResult:
        if not settings.semgrep_enabled:
            return SemgrepScanResult(
                enabled=False,
                rules_root=str(self.rules_root),
                rules_indexed=0,
                rules_selected=0,
                findings=[],
                selection_rationale={},
            )

        if not self.rules_root.exists():
            return SemgrepScanResult(
                enabled=True,
                rules_root=str(self.rules_root),
                rules_indexed=0,
                rules_selected=0,
                findings=[],
                selection_rationale={},
                error=f"Rules root not found: {self.rules_root}",
            )

        index = self._load_or_build_index()
        selected = select_rules_for_repo(index.records, scan_result, self.rules_root)
        if not selected.selected_rule_paths:
            return SemgrepScanResult(
                enabled=True,
                rules_root=str(self.rules_root),
                rules_indexed=index.total_rules_indexed,
                rules_selected=0,
                findings=[],
                selection_rationale=selected.rationale,
            )

        raw_output, error = self._run_semgrep(selected)
        if error:
            return SemgrepScanResult(
                enabled=True,
                rules_root=str(self.rules_root),
                rules_indexed=index.total_rules_indexed,
                rules_selected=len(selected.selected_rules),
                findings=[],
                selection_rationale=selected.rationale,
                error=error,
            )

        findings = self._normalize_results(raw_output, selected.selected_rules)
        return SemgrepScanResult(
            enabled=True,
            rules_root=str(self.rules_root),
            rules_indexed=index.total_rules_indexed,
            rules_selected=len(selected.selected_rules),
            findings=findings,
            selection_rationale=selected.rationale,
        )

    def _load_or_build_index(self) -> RuleIndex:
        cache_path = Path(settings.semgrep_index_cache_file)
        if not cache_path.is_absolute():
            cache_path = Path(__file__).resolve().parent.parent / cache_path

        if cache_path.exists():
            try:
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                records = [RuleRecord(**record) for record in data.get("records", [])]
                return RuleIndex(
                    generated_at_utc=data.get("generated_at_utc", ""),
                    rules_root=data.get("rules_root", str(self.rules_root)),
                    repo_commit_sha=data.get("repo_commit_sha", ""),
                    total_files_scanned=int(data.get("total_files_scanned", 0)),
                    total_rules_indexed=int(data.get("total_rules_indexed", len(records))),
                    records=records,
                )
            except Exception as exc:
                logger.info("[SemgrepRunner] Could not load cached index: %s", exc)

        indexer = SemgrepRuleIndexer(self.rules_root)
        return indexer.build_to_file(cache_path)

    def _run_semgrep(self, selection: RuleSelectionResult) -> tuple[Dict[str, Any], str]:
        cmd = [
            settings.semgrep_binary,
            "scan",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--timeout",
            str(settings.semgrep_timeout_sec),
            str(self.repo_path),
        ]
        for path in selection.selected_rule_paths:
            cmd.extend(["--config", str(path)])

        try:
            env = os.environ.copy()
            if settings.semgrep_app_token:
                env["SEMGREP_APP_TOKEN"] = settings.semgrep_app_token
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
        except FileNotFoundError:
            return {}, "Semgrep binary not found. Install semgrep or set SEMGREP_BINARY."
        except Exception as exc:
            return {}, f"Failed to execute Semgrep: {exc}"

        if proc.returncode not in {0, 1}:
            stderr = (proc.stderr or "").strip()
            return {}, f"Semgrep failed with code {proc.returncode}: {stderr}"

        try:
            return json.loads(proc.stdout or "{}"), ""
        except json.JSONDecodeError as exc:
            return {}, f"Semgrep output parse failed: {exc}"

    def _normalize_results(
        self,
        semgrep_output: Dict[str, Any],
        selected_rules: List[RuleRecord],
    ) -> List[SemgrepFinding]:
        by_rule_id: Dict[str, List[RuleRecord]] = {}
        for rule in selected_rules:
            by_rule_id.setdefault(rule.rule_id, []).append(rule)

        findings: List[SemgrepFinding] = []
        results = semgrep_output.get("results", [])
        if not isinstance(results, list):
            return findings

        for item in results:
            if not isinstance(item, dict):
                continue

            rule_id = str(item.get("check_id", "")).strip()
            path_raw = str(item.get("path", "")).strip()
            if not path_raw:
                continue
            file_path = (self.repo_path / path_raw).resolve() if not Path(path_raw).is_absolute() else Path(path_raw)
            start = item.get("start", {}) if isinstance(item.get("start", {}), dict) else {}
            end = item.get("end", {}) if isinstance(item.get("end", {}), dict) else {}
            extra = item.get("extra", {}) if isinstance(item.get("extra", {}), dict) else {}
            metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata", {}), dict) else {}

            matched_rule = by_rule_id.get(rule_id, [None])[0]
            if matched_rule is not None:
                category = matched_rule.category
                subcategory = matched_rule.subcategory
                cwe = matched_rule.cwe
                owasp = matched_rule.owasp
                refs = matched_rule.references
                source_rule_url = matched_rule.source_rule_url
                technology = matched_rule.technology
                confidence = matched_rule.confidence
                likelihood = matched_rule.likelihood
                impact = matched_rule.impact
                rule_path = matched_rule.rule_path
                mode = matched_rule.mode
            else:
                category = str(metadata.get("category", ""))
                subcategory = self._to_list(metadata.get("subcategory"))
                cwe = self._to_list(metadata.get("cwe"))
                owasp = self._to_list(metadata.get("owasp"))
                refs = self._to_list(metadata.get("references"))
                source_rule_url = str(metadata.get("source-rule-url", ""))
                technology = self._to_list(metadata.get("technology"))
                confidence = str(metadata.get("confidence", "")).upper()
                likelihood = str(metadata.get("likelihood", "")).upper()
                impact = str(metadata.get("impact", "")).upper()
                rule_path = ""
                mode = str(extra.get("engine_kind", "pattern"))

            findings.append(
                SemgrepFinding(
                    rule_id=rule_id,
                    file=str(file_path),
                    line=int(start.get("line", 0) or 0),
                    end_line=int(end.get("line", 0) or 0),
                    severity=str(extra.get("severity", "UNKNOWN")).upper(),
                    message=str(extra.get("message", "")),
                    snippet=str(extra.get("lines", "")).strip(),
                    category=category,
                    subcategory=subcategory,
                    cwe=cwe,
                    owasp=owasp,
                    references=refs,
                    source_rule_url=source_rule_url,
                    technology=technology,
                    confidence=confidence,
                    likelihood=likelihood,
                    impact=impact,
                    rule_path=rule_path,
                    mode=mode,
                )
            )

        return findings

    @staticmethod
    def _to_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        if isinstance(value, str):
            return [value]
        return [str(value)]
