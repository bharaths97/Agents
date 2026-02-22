from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

                terminal_output = outputs_by_file.get(terminal_file)
                terminal_has_findings = bool(terminal_output and terminal_output.taint_findings)
                terminal_finding_ids = (
                    [finding.id for finding in terminal_output.taint_findings]
                    if terminal_output
                    else []
                )

                if terminal_has_findings:
                    note = (
                        f"Cross-file chain to {Path(terminal_file).name}::{terminal_fn} "
                        f"linked with finalized findings in terminal file."
                    )
                    confidence = 0.45
                    status = "linked_to_terminal_finding"
                else:
                    note = (
                        f"Cross-file chain to {Path(terminal_file).name}::{terminal_fn} "
                        "was detected but unresolved by final taint findings."
                    )
                    confidence = 0.30
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
    def _norm_file(file_path: str) -> str:
        if not file_path:
            return file_path
        try:
            return str(Path(file_path).resolve())
        except Exception:
            return file_path
