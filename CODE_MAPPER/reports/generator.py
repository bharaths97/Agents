from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any, Dict, List


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class ReportGenerator:
    """Render human-readable reports from the orchestrator JSON payload."""

    def generate_all(
        self,
        payload: Dict[str, Any],
        output_dir: Path,
        base_stem: str,
    ) -> Dict[str, Path]:
        markdown_path = output_dir / f"{base_stem}.md"
        html_path = output_dir / f"{base_stem}.html"
        tickets_path = output_dir / f"{base_stem}_tickets.json"

        markdown_path.write_text(self.render_markdown(payload), encoding="utf-8")
        html_path.write_text(self.render_html(payload), encoding="utf-8")
        tickets_path.write_text(json.dumps(self.build_tickets(payload), indent=2), encoding="utf-8")

        return {
            "markdown": markdown_path,
            "html": html_path,
            "tickets": tickets_path,
        }

    def render_markdown(self, payload: Dict[str, Any]) -> str:
        results = payload.get("results", {})
        summary = payload.get("summary", {})
        correlated = list(results.get("correlated_findings", []) or [])
        threat_model = results.get("threat_model", {}) or {}
        ctf_artifacts = results.get("ctf_artifacts", {}) or {}
        domain = ((results.get("agent_1a", {}) or {}).get("domain", "unknown"))
        risk_tier = ((results.get("agent_1a", {}) or {}).get("domain_risk_tier", "unknown"))

        lines: List[str] = []
        lines.append("# CODE_MAPPER Security Report")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(f"- Generated: `{payload.get('generated_at_utc', 'unknown')}`")
        lines.append(f"- Repository: `{payload.get('repo_path', 'unknown')}`")
        lines.append(f"- Model: `{payload.get('model', 'unknown')}`")
        lines.append(f"- Domain: `{domain}`")
        lines.append(f"- Domain Risk Tier: `{risk_tier}`")
        lines.append(f"- Correlated Findings: `{summary.get('correlated_findings', 0)}`")
        lines.append(f"- Taint Findings (raw): `{summary.get('taint_findings', 0)}`")
        lines.append(f"- Threat Scenarios: `{summary.get('threat_scenarios', 0)}`")
        lines.append("")

        top_scenarios = list((threat_model.get("prioritized_threat_scenarios", []) or []))[:3]
        lines.append("### Top Threat Scenarios")
        if top_scenarios:
            for item in top_scenarios:
                lines.append(
                    f"- `{item.get('scenario_id', 'TS-?')}` "
                    f"(rank `{item.get('rank', '?')}`, risk `{item.get('risk_score', '?')}`): "
                    f"{item.get('title', 'Untitled')}"
                )
        else:
            lines.append("- None")
        lines.append("")

        lines.append("## Findings by Severity")
        lines.append("| Severity | Count |")
        lines.append("|---|---:|")
        for severity in SEVERITY_ORDER:
            count = len([item for item in correlated if str(item.get("severity", "")).upper() == severity])
            lines.append(f"| {severity} | {count} |")
        lines.append("")

        lines.append("## Correlated Findings")
        if not correlated:
            lines.append("_No correlated findings were produced._")
        else:
            for item in correlated:
                lines.extend(self._finding_markdown(item))
        lines.append("")

        lines.append("## STRIDE Threat Model")
        lines.append(f"- Methodology: `{threat_model.get('methodology', 'STRIDE')}`")
        lines.append(f"- Assets: `{len(threat_model.get('assets', []) or [])}`")
        lines.append(f"- Trust Boundaries: `{len(threat_model.get('trust_boundaries', []) or [])}`")
        lines.append(f"- Attack Surface Entries: `{len(threat_model.get('attack_surface', []) or [])}`")
        lines.append(f"- STRIDE Threat Entries: `{len(threat_model.get('stride_analysis', []) or [])}`")
        lines.append("")
        lines.append("### Prioritized Threat Scenarios")
        if top_scenarios:
            for item in top_scenarios:
                lines.append(
                    f"- `{item.get('scenario_id', 'TS-?')}` rank `{item.get('rank', '?')}` "
                    f"risk `{item.get('risk_score', '?')}`: {item.get('narrative', '')}"
                )
        else:
            lines.append("- None")
        lines.append("")

        lines.append("## CTF Artifacts")
        hits = list(ctf_artifacts.get("hits", []) or [])
        if not hits:
            lines.append("_No CTF artifacts found._")
        else:
            lines.append(f"- Summary: {ctf_artifacts.get('summary', '')}")
            for hit in hits:
                lines.append(
                    f"- `{hit.get('match', '')}` in `{hit.get('file', '')}` "
                    f"(lines {hit.get('line_start', '?')}-{hit.get('line_end', '?')})"
                )
        lines.append("")
        return "\n".join(lines)

    def render_html(self, payload: Dict[str, Any]) -> str:
        results = payload.get("results", {})
        summary = payload.get("summary", {})
        correlated = list(results.get("correlated_findings", []) or [])
        threat_model = results.get("threat_model", {}) or {}
        ctf_artifacts = results.get("ctf_artifacts", {}) or {}
        domain = ((results.get("agent_1a", {}) or {}).get("domain", "unknown"))
        risk_tier = ((results.get("agent_1a", {}) or {}).get("domain_risk_tier", "unknown"))
        top_scenarios = list((threat_model.get("prioritized_threat_scenarios", []) or []))[:3]

        severity_rows = []
        for severity in SEVERITY_ORDER:
            count = len([item for item in correlated if str(item.get("severity", "")).upper() == severity])
            severity_rows.append(f"<tr><td>{escape(severity)}</td><td>{count}</td></tr>")

        finding_blocks = []
        if correlated:
            for finding in correlated:
                finding_blocks.append(self._finding_html_block(finding))
        else:
            finding_blocks.append("<p>No correlated findings were produced.</p>")

        if top_scenarios:
            scenario_items = "".join(
                f"<li><strong>{escape(str(item.get('scenario_id', 'TS-?')))}</strong> "
                f"(rank {escape(str(item.get('rank', '?')))}, risk {escape(str(item.get('risk_score', '?')))}): "
                f"{escape(str(item.get('title', 'Untitled')))}</li>"
                for item in top_scenarios
            )
        else:
            scenario_items = "<li>None</li>"

        ctf_hits = list(ctf_artifacts.get("hits", []) or [])
        if ctf_hits:
            ctf_list = "".join(
                f"<li><code>{escape(str(hit.get('match', '')))}</code> in "
                f"<code>{escape(str(hit.get('file', '')))}</code> "
                f"(lines {escape(str(hit.get('line_start', '?')))}-{escape(str(hit.get('line_end', '?')))}"
                f")</li>"
                for hit in ctf_hits
            )
        else:
            ctf_list = "<li>No CTF artifacts found.</li>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CODE_MAPPER Security Report</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --text: #1f2937;
      --muted: #6b7280;
      --border: #d1d5db;
      --accent: #0f766e;
      --critical: #b91c1c;
      --high: #b45309;
      --medium: #1d4ed8;
      --low: #4b5563;
    }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", Tahoma, sans-serif; }}
    main {{ max-width: 1080px; margin: 0 auto; padding: 24px; }}
    h1, h2, h3 {{ margin: 0 0 12px 0; }}
    section {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; border-bottom: 1px solid var(--border); padding: 8px; vertical-align: top; }}
    code {{ background: #eef2ff; padding: 2px 4px; border-radius: 4px; }}
    pre {{ background: #0b1020; color: #f9fafb; padding: 10px; border-radius: 6px; overflow-x: auto; }}
    .meta {{ color: var(--muted); font-size: 0.95rem; }}
    .sev-CRITICAL {{ color: var(--critical); font-weight: 700; }}
    .sev-HIGH {{ color: var(--high); font-weight: 700; }}
    .sev-MEDIUM {{ color: var(--medium); font-weight: 700; }}
    .sev-LOW {{ color: var(--low); font-weight: 700; }}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>CODE_MAPPER Security Report</h1>
      <p class="meta">Generated: {escape(str(payload.get("generated_at_utc", "unknown")))}<br />
      Repository: <code>{escape(str(payload.get("repo_path", "unknown")))}</code><br />
      Model: <code>{escape(str(payload.get("model", "unknown")))}</code></p>
      <p><strong>Domain:</strong> {escape(str(domain))} |
      <strong>Risk Tier:</strong> <code>{escape(str(risk_tier))}</code> |
      <strong>Correlated Findings:</strong> {escape(str(summary.get("correlated_findings", 0)))}</p>
    </section>

    <section>
      <h2>Top Threat Scenarios</h2>
      <ul>{scenario_items}</ul>
    </section>

    <section>
      <h2>Findings by Severity</h2>
      <table>
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>{''.join(severity_rows)}</tbody>
      </table>
    </section>

    <section>
      <h2>Correlated Findings</h2>
      {''.join(finding_blocks)}
    </section>

    <section>
      <h2>STRIDE Threat Model</h2>
      <ul>
        <li>Assets: {len(threat_model.get("assets", []) or [])}</li>
        <li>Trust Boundaries: {len(threat_model.get("trust_boundaries", []) or [])}</li>
        <li>Attack Surface Entries: {len(threat_model.get("attack_surface", []) or [])}</li>
        <li>STRIDE Entries: {len(threat_model.get("stride_analysis", []) or [])}</li>
      </ul>
    </section>

    <section>
      <h2>CTF Artifacts</h2>
      <p>{escape(str(ctf_artifacts.get("summary", "")))}</p>
      <ul>{ctf_list}</ul>
    </section>
  </main>
</body>
</html>
"""

    def build_tickets(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        correlated = list((payload.get("results", {}) or {}).get("correlated_findings", []) or [])
        tickets: List[Dict[str, Any]] = []
        for item in correlated:
            severity = str(item.get("severity", "")).upper()
            if severity not in {"CRITICAL", "HIGH"}:
                continue
            rep = item.get("representative_finding", {}) or {}
            source = rep.get("source", {}) or {}
            sink = rep.get("sink", {}) or {}
            file_name = self._primary_file(item)
            correlation_id = str(item.get("correlation_id", "CF-UNKNOWN"))
            title = (
                f"[{severity}] {rep.get('vulnerability', item.get('vulnerability', 'Security finding'))} "
                f"in {file_name}"
            )
            description = (
                f"CWE: {item.get('cwe', 'unknown')}\n"
                f"Confidence: {item.get('confidence_adjusted', item.get('confidence_base', 'unknown'))}\n"
                f"Source line: {source.get('line', 'unknown')}\n"
                f"Sink line: {sink.get('line', 'unknown')}\n"
                f"Exploit scenario: {rep.get('exploit_scenario', '')}\n"
                f"Remediation: {rep.get('remediation', '')}"
            )
            tickets.append(
                {
                    "ticket_id": f"TICKET-{correlation_id}",
                    "source_correlation_id": correlation_id,
                    "priority": severity,
                    "title": title,
                    "description": description,
                    "acceptance_criteria": [
                        "Tainted input no longer reaches dangerous sink without sink-appropriate sanitization.",
                        "Regression test added to cover exploit scenario and secure path.",
                        "Code review validates remediation against CWE and threat scenario context.",
                    ],
                    "evidence_refs": [
                        {
                            "file": file_name,
                            "source_line": source.get("line"),
                            "sink_line": sink.get("line"),
                            "cwe": item.get("cwe"),
                        }
                    ],
                }
            )
        return tickets

    def _finding_markdown(self, item: Dict[str, Any]) -> List[str]:
        rep = item.get("representative_finding", {}) or {}
        source = rep.get("source", {}) or {}
        sink = rep.get("sink", {}) or {}
        lines: List[str] = []
        lines.append(
            f"### {item.get('correlation_id', 'CF-?')} - "
            f"{item.get('severity', 'UNKNOWN')} - {item.get('vulnerability', 'Unknown')}"
        )
        lines.append(f"- CWE: `{item.get('cwe', 'unknown')}`")
        lines.append(f"- Files: `{', '.join(item.get('files', []) or [])}`")
        lines.append(f"- Confidence: `{item.get('confidence_adjusted', 'unknown')}`")
        lines.append(f"- Rank Score: `{item.get('rank_score', 'unknown')}`")
        lines.append(f"- Source Agents: `{', '.join(item.get('source_agents', []) or [])}`")
        lines.append(
            f"- Source -> Sink: line `{source.get('line', '?')}` -> line `{sink.get('line', '?')}` "
            f"({sink.get('sink_fn', 'unknown sink')})"
        )
        if rep.get("taint_path"):
            lines.append("- Taint Path:")
            for step in rep.get("taint_path", []):
                lines.append(f"  - {step}")
        if rep.get("crosses_file_boundary") and rep.get("boundary_hops"):
            lines.append("- Cross-File Boundary Hops:")
            for hop in rep.get("boundary_hops", []):
                lines.append(
                    "  - "
                    f"{hop.get('from_file', '?')}::{hop.get('from_function', '?')} "
                    f"-> {hop.get('to_file', '?')}::{hop.get('to_function', '?')} "
                    f"(line {hop.get('call_line', '?')})"
                )
        snippet = rep.get("snippet", "")
        if snippet:
            lines.append("- Snippet:")
            lines.append("```text")
            lines.append(str(snippet))
            lines.append("```")
        lines.append(f"- Exploit Scenario: {rep.get('exploit_scenario', '')}")
        lines.append(f"- Remediation: {rep.get('remediation', '')}")
        lines.append("")
        return lines

    def _finding_html_block(self, item: Dict[str, Any]) -> str:
        rep = item.get("representative_finding", {}) or {}
        source = rep.get("source", {}) or {}
        sink = rep.get("sink", {}) or {}
        severity = escape(str(item.get("severity", "UNKNOWN")).upper())
        taint_path_items = "".join(
            f"<li>{escape(str(step))}</li>" for step in (rep.get("taint_path", []) or [])
        )
        boundary_items = ""
        if rep.get("crosses_file_boundary") and rep.get("boundary_hops"):
            boundary_items = "".join(
                "<li>"
                f"{escape(str(hop.get('from_file', '?')))}::{escape(str(hop.get('from_function', '?')))} "
                f"-&gt; {escape(str(hop.get('to_file', '?')))}::{escape(str(hop.get('to_function', '?')))} "
                f"(line {escape(str(hop.get('call_line', '?')))})"
                "</li>"
                for hop in rep.get("boundary_hops", [])
            )
        snippet = rep.get("snippet", "")
        snippet_html = f"<pre><code>{escape(str(snippet))}</code></pre>" if snippet else ""
        return (
            "<article style=\"border:1px solid #d1d5db;border-radius:8px;padding:12px;margin-bottom:12px;\">"
            f"<h3>{escape(str(item.get('correlation_id', 'CF-?')))} "
            f"<span class=\"sev-{severity}\">{severity}</span> "
            f"{escape(str(item.get('vulnerability', 'Unknown')))}</h3>"
            f"<p><strong>CWE:</strong> <code>{escape(str(item.get('cwe', 'unknown')))}</code> | "
            f"<strong>Confidence:</strong> {escape(str(item.get('confidence_adjusted', 'unknown')))} | "
            f"<strong>Rank:</strong> {escape(str(item.get('rank_score', 'unknown')))}</p>"
            f"<p><strong>Files:</strong> <code>{escape(', '.join(item.get('files', []) or []))}</code><br />"
            f"<strong>Source -&gt; Sink:</strong> line {escape(str(source.get('line', '?')))} "
            f"-&gt; line {escape(str(sink.get('line', '?')))} ({escape(str(sink.get('sink_fn', 'unknown sink')))}"
            f")</p>"
            f"<p><strong>Source Agents:</strong> {escape(', '.join(item.get('source_agents', []) or []))}</p>"
            f"<h4>Taint Path</h4><ul>{taint_path_items or '<li>None</li>'}</ul>"
            + (
                f"<h4>Cross-File Boundary Hops</h4><ul>{boundary_items}</ul>"
                if boundary_items
                else ""
            )
            + snippet_html
            + f"<p><strong>Exploit Scenario:</strong> {escape(str(rep.get('exploit_scenario', '')))}</p>"
            + f"<p><strong>Remediation:</strong> {escape(str(rep.get('remediation', '')))}</p>"
            + "</article>"
        )

    @staticmethod
    def _primary_file(item: Dict[str, Any]) -> str:
        files = list(item.get("files", []) or [])
        if files:
            return files[0]
        rep = item.get("representative_finding", {}) or {}
        source = rep.get("source", {}) or {}
        return str(source.get("file", "unknown"))
