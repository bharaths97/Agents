from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from schemas.models import Agent1eOutput, TaintFinding


class FindingsCorrelator:
    """
    Phase 2 correlator:
    - Deduplicates similar taint findings
    - Correlates Semgrep and Phase 3 link evidence
    - Produces a deterministic ranked list for downstream reporting
    """

    _SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    def correlate(
        self,
        outputs: List[Agent1eOutput],
        semgrep_findings_by_file: Dict[str, List[Dict[str, Any]]] | None = None,
        phase3_links: List[Dict[str, Any]] | None = None,
    ) -> List[Dict[str, Any]]:
        if not outputs:
            return []

        semgrep_index = self._normalize_semgrep_index(semgrep_findings_by_file or {})
        phase3_links = phase3_links or []

        clusters: Dict[str, List[Tuple[str, TaintFinding]]] = {}
        for output in outputs:
            file_key = self._norm_file(output.file)
            for finding in output.taint_findings:
                dedup_key = self._dedup_key(file_key, finding)
                clusters.setdefault(dedup_key, []).append((file_key, finding))

        correlated: List[Dict[str, Any]] = []
        for dedup_key in sorted(clusters):
            cluster = clusters[dedup_key]
            representative = self._pick_representative(cluster)
            files = sorted({file_path for file_path, _ in cluster})
            merged_ids = sorted({item.id for _, item in cluster})

            semgrep_hits = self._match_semgrep_hits(representative, files, semgrep_index)
            link_hits = self._match_phase3_links(merged_ids, files, phase3_links)

            source_agents = {"1E"}
            if semgrep_hits:
                source_agents.add("SEMGREP")
            if link_hits:
                source_agents.add("PHASE3_LINKER")

            confidence_base = float(representative.confidence)
            confidence_adjusted = self._adjust_confidence(
                base=confidence_base,
                duplicates=len(cluster),
                semgrep_hits=len(semgrep_hits),
                phase3_links=link_hits,
                false_positive_risk=representative.false_positive_risk,
            )
            rank_score = self._rank_score(
                severity=representative.severity,
                confidence=confidence_adjusted,
                evidence_count=(len(cluster) + len(semgrep_hits) + len(link_hits)),
                domain_context=representative.domain_risk_context,
            )

            evidence_set = self._build_evidence_set(cluster, semgrep_hits, link_hits)
            correlated.append(
                {
                    "correlation_id": "",
                    "dedup_key": dedup_key,
                    "severity": representative.severity,
                    "cwe": representative.cwe,
                    "vulnerability": representative.vulnerability,
                    "files": files,
                    "source_agents": sorted(source_agents),
                    "merged_finding_ids": merged_ids,
                    "confidence_base": round(confidence_base, 4),
                    "confidence_adjusted": confidence_adjusted,
                    "rank_score": rank_score,
                    "evidence_summary": {
                        "taint_findings": len(cluster),
                        "semgrep_hits": len(semgrep_hits),
                        "phase3_links": len(link_hits),
                    },
                    "evidence_set": evidence_set,
                    "representative_finding": representative.model_dump(),
                }
            )

        correlated.sort(key=lambda item: (-item["rank_score"], item["dedup_key"]))
        for idx, item in enumerate(correlated, start=1):
            item["correlation_id"] = f"CF-{idx:03d}"
        return correlated

    def _pick_representative(self, cluster: List[Tuple[str, TaintFinding]]) -> TaintFinding:
        return sorted(
            (finding for _, finding in cluster),
            key=lambda f: (
                -float(f.confidence),
                -self._SEVERITY_WEIGHT.get(f.severity, 1),
                str(f.id),
            ),
        )[0]

    def _match_semgrep_hits(
        self,
        finding: TaintFinding,
        files: List[str],
        semgrep_index: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        sink_line = int(finding.sink.get("line", 0) or 0)
        source_line = int(finding.source.get("line", 0) or 0)
        cwe = self._norm_cwe(finding.cwe)
        matches: List[Dict[str, Any]] = []

        for file_path in files:
            for hit in semgrep_index.get(file_path, []):
                hit_cwes = {self._norm_cwe(value) for value in hit.get("cwe", [])}
                if cwe and cwe not in hit_cwes:
                    continue

                hit_line = int(hit.get("line", 0) or 0)
                close_to_sink = sink_line > 0 and hit_line > 0 and abs(hit_line - sink_line) <= 10
                close_to_source = source_line > 0 and hit_line > 0 and abs(hit_line - source_line) <= 10
                if not (close_to_sink or close_to_source):
                    continue

                matches.append(hit)

        # Deduplicate by rule/line/file so repeated runs do not inflate confidence.
        deduped: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
        for hit in matches:
            key = (
                str(hit.get("rule_id", "")),
                self._norm_file(str(hit.get("file", ""))),
                int(hit.get("line", 0) or 0),
            )
            deduped.setdefault(key, hit)
        return [deduped[key] for key in sorted(deduped)]

    def _match_phase3_links(
        self,
        merged_ids: List[str],
        files: List[str],
        phase3_links: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        merged_set = set(merged_ids)
        file_set = set(files)
        matched: List[Dict[str, Any]] = []

        for link in phase3_links:
            terminal_ids = set(link.get("terminal_finding_ids", []) or [])
            source_file = self._norm_file(str(link.get("source_file", "")))
            terminal_file = self._norm_file(str(link.get("terminal_file", "")))

            if terminal_ids.intersection(merged_set):
                matched.append(link)
                continue
            if source_file in file_set or terminal_file in file_set:
                matched.append(link)

        deduped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for link in matched:
            key = (
                self._norm_file(str(link.get("source_file", ""))),
                self._norm_file(str(link.get("terminal_file", ""))),
                str(link.get("chain_signature", "")),
            )
            deduped.setdefault(key, link)
        return [deduped[key] for key in sorted(deduped)]

    def _adjust_confidence(
        self,
        base: float,
        duplicates: int,
        semgrep_hits: int,
        phase3_links: List[Dict[str, Any]],
        false_positive_risk: str,
    ) -> float:
        adjusted = base

        if duplicates > 1:
            adjusted += min(0.06, 0.03 * (duplicates - 1))
        if semgrep_hits > 0:
            adjusted += min(0.12, 0.04 * semgrep_hits)

        has_terminal_link = any(
            str(link.get("status", "")) == "linked_to_terminal_finding"
            for link in phase3_links
        )
        has_unresolved_link = any(
            str(link.get("status", "")) == "unresolved_chain"
            for link in phase3_links
        )
        if has_terminal_link:
            adjusted += 0.03
        elif has_unresolved_link and semgrep_hits == 0:
            adjusted -= 0.03

        risk = str(false_positive_risk).upper()
        if risk == "HIGH":
            adjusted -= 0.05
        elif risk == "MEDIUM":
            adjusted -= 0.02

        return round(max(0.05, min(0.99, adjusted)), 4)

    def _rank_score(
        self,
        severity: str,
        confidence: float,
        evidence_count: int,
        domain_context: str,
    ) -> float:
        severity_weight = self._SEVERITY_WEIGHT.get(str(severity).upper(), 1)
        domain_multiplier = self._domain_multiplier(domain_context)
        raw = (severity_weight * 20.0) + (confidence * 70.0) + min(20.0, evidence_count * 2.5)
        return round(raw * domain_multiplier, 4)

    def _build_evidence_set(
        self,
        cluster: List[Tuple[str, TaintFinding]],
        semgrep_hits: List[Dict[str, Any]],
        link_hits: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        evidence: List[Dict[str, Any]] = []
        for file_path, finding in cluster:
            evidence.append(
                {
                    "source": "1E",
                    "file": file_path,
                    "finding_id": finding.id,
                    "line_source": int(finding.source.get("line", 0) or 0),
                    "line_sink": int(finding.sink.get("line", 0) or 0),
                    "snippet": finding.snippet or "",
                }
            )
        for hit in semgrep_hits:
            evidence.append(
                {
                    "source": "SEMGREP",
                    "file": self._norm_file(str(hit.get("file", ""))),
                    "rule_id": str(hit.get("rule_id", "")),
                    "line": int(hit.get("line", 0) or 0),
                    "message": str(hit.get("message", "")),
                }
            )
        for link in link_hits:
            evidence.append(
                {
                    "source": "PHASE3_LINKER",
                    "source_file": self._norm_file(str(link.get("source_file", ""))),
                    "terminal_file": self._norm_file(str(link.get("terminal_file", ""))),
                    "chain_length": int(link.get("chain_length", 0) or 0),
                    "status": str(link.get("status", "")),
                }
            )
        return evidence

    def _dedup_key(self, file_key: str, finding: TaintFinding) -> str:
        source_line = int(finding.source.get("line", 0) or 0)
        sink_line = int(finding.sink.get("line", 0) or 0)
        sink_fn = self._norm_symbol(str(finding.sink.get("sink_fn", "")))
        cwe = self._norm_cwe(finding.cwe)
        vuln = self._norm_symbol(finding.vulnerability)
        return f"{file_key}|{cwe}|{vuln}|{sink_fn}|{source_line}|{sink_line}"

    def _normalize_semgrep_index(
        self,
        semgrep_findings_by_file: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        index: Dict[str, List[Dict[str, Any]]] = {}
        for file_path, hits in semgrep_findings_by_file.items():
            key = self._norm_file(file_path)
            normalized_hits: List[Dict[str, Any]] = []
            for hit in hits:
                if not isinstance(hit, dict):
                    continue
                data = dict(hit)
                data["file"] = self._norm_file(str(data.get("file", file_path)))
                cwe_values = data.get("cwe", [])
                data["cwe"] = [
                    self._norm_cwe(value)
                    for value in self._to_list(cwe_values)
                    if self._norm_cwe(value)
                ]
                normalized_hits.append(data)
            index.setdefault(key, []).extend(normalized_hits)
        return index

    @staticmethod
    def _to_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        if isinstance(value, str):
            return [value]
        return [str(value)]

    @staticmethod
    def _norm_cwe(value: Any) -> str:
        raw = str(value or "").strip().upper()
        if not raw:
            return ""
        if raw.startswith("CWE-"):
            return raw
        if raw.isdigit():
            return f"CWE-{raw}"
        return raw

    @staticmethod
    def _norm_symbol(value: str) -> str:
        cleaned = value.strip().lower()
        return "".join(ch for ch in cleaned if ch.isalnum() or ch in {"_", ".", ":"})

    @staticmethod
    def _norm_file(file_path: str) -> str:
        if not file_path:
            return file_path
        try:
            return str(Path(file_path).resolve())
        except Exception:
            return file_path

    @staticmethod
    def _domain_multiplier(domain_context: str) -> float:
        text = str(domain_context or "").upper()
        if "CRITICAL" in text:
            return 1.20
        if "HIGH" in text:
            return 1.10
        if "LOW" in text:
            return 0.95
        return 1.00
