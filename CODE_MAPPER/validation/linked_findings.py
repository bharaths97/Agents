from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from schemas.models import Agent1eOutput, LowConfidenceObservation


class LinkedFindingsResolver:
    """
    Light Option-B fallback linker for unresolved cross-file chains.

    It does not create new high-severity findings. It only adds structured
    low-confidence observations when call-chain hints suggest a cross-file
    relationship that 1e may not have finalized.
    """

    def link_outputs(
        self,
        outputs: List[Agent1eOutput],
        call_graph_index=None,
    ) -> Tuple[List[Agent1eOutput], List[Dict[str, Any]]]:
        if not outputs:
            return outputs, []
        if call_graph_index is None:
            return outputs, []

        outputs_by_file: Dict[str, Agent1eOutput] = {
            self._norm_file(output.file): output for output in outputs
        }
        linked_records: List[Dict[str, Any]] = []
        seen_chain_signatures: Set[Tuple[str, str, str]] = set()
        updated_outputs: List[Agent1eOutput] = []

        for output in outputs:
            file_key = self._norm_file(output.file)
            try:
                hints = call_graph_index.file_hints(file_key)
            except Exception:
                updated_outputs.append(output)
                continue

            observations = list(output.low_confidence_observations)
            existing_keys = {
                (item.source_variable, item.sink_fn, item.note)
                for item in observations
            }

            for chain in hints.get("call_chains", []):
                terminal_file = self._norm_file(chain.get("terminal_file", ""))
                terminal_fn = str(chain.get("terminal_function", "unknown"))
                start_fn = str(chain.get("start_function", "unknown"))
                chain_length = int(chain.get("chain_length", 0) or 0)
                if chain_length <= 0:
                    continue
                chain_signature = self._chain_signature(chain)
                dedupe_key = (file_key, terminal_file, chain_signature)
                if dedupe_key in seen_chain_signatures:
                    continue
                seen_chain_signatures.add(dedupe_key)

                terminal_output = outputs_by_file.get(terminal_file)
                terminal_has_findings = bool(terminal_output and terminal_output.taint_findings)
                already_covered = self._is_chain_already_covered(output, chain)
                terminal_finding_ids = (
                    [finding.id for finding in terminal_output.taint_findings]
                    if terminal_output
                    else []
                )
                if already_covered:
                    continue

                if terminal_has_findings:
                    note = (
                        f"Cross-file chain to {Path(terminal_file).name}::{terminal_fn} "
                        f"linked with finalized findings in terminal file."
                    )
                    confidence = self._link_confidence(chain_length, linked_to_terminal=True)
                    status = "linked_to_terminal_finding"
                else:
                    if chain_length < 2:
                        # Keep the fallback conservative: unresolved single-hop links are noisy.
                        continue
                    note = (
                        f"Cross-file chain to {Path(terminal_file).name}::{terminal_fn} "
                        f"({chain_length} hop chain) was detected but unresolved by final taint findings."
                    )
                    confidence = self._link_confidence(chain_length, linked_to_terminal=False)
                    status = "unresolved_chain"

                key = (start_fn, terminal_fn, note)
                if key not in existing_keys:
                    observations.append(
                        LowConfidenceObservation(
                            source_variable=start_fn,
                            sink_fn=terminal_fn,
                            note=note,
                            confidence=confidence,
                        )
                    )
                    existing_keys.add(key)

                linked_records.append(
                    {
                        "source_file": file_key,
                        "source_function": start_fn,
                        "terminal_file": terminal_file,
                        "terminal_function": terminal_fn,
                        "chain_length": chain_length,
                        "chain_signature": chain_signature,
                        "confidence": confidence,
                        "status": status,
                        "terminal_finding_ids": terminal_finding_ids,
                    }
                )

            updated_outputs.append(
                output.model_copy(
                    update={"low_confidence_observations": observations}
                )
            )

        return updated_outputs, linked_records

    @staticmethod
    def _chain_signature(chain: Dict[str, Any]) -> str:
        hops = chain.get("hops", []) or []
        tokens = []
        for hop in hops:
            tokens.append(
                f"{hop.get('from_file','')}::{hop.get('from_function','')}"
                f"->{hop.get('to_file','')}::{hop.get('to_function','')}"
                f"@{hop.get('call_line',0)}"
            )
        return "|".join(tokens) if tokens else "no-hops"

    def _is_chain_already_covered(self, output: Agent1eOutput, chain: Dict[str, Any]) -> bool:
        hops = chain.get("hops", []) or []
        if not hops:
            return False
        terminal_hop = hops[-1]
        terminal_file = self._norm_file(terminal_hop.get("to_file", ""))
        terminal_fn = str(terminal_hop.get("to_function", ""))
        for finding in output.taint_findings:
            if not finding.crosses_file_boundary:
                continue
            boundary_hops = finding.boundary_hops or []
            if not boundary_hops:
                continue
            last = boundary_hops[-1]
            if (
                self._norm_file(last.get("to_file", "")) == terminal_file
                and str(last.get("to_function", "")) == terminal_fn
            ):
                return True
        return False

    @staticmethod
    def _link_confidence(chain_length: int, linked_to_terminal: bool) -> float:
        base = 0.45 if linked_to_terminal else 0.30
        decay = 0.04 * max(0, chain_length - 1)
        confidence = base - decay
        return round(max(0.15, confidence), 2)

    @staticmethod
    def _norm_file(file_path: str) -> str:
        if not file_path:
            return file_path
        try:
            return str(Path(file_path).resolve())
        except Exception:
            return file_path
