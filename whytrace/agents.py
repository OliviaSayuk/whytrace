
from __future__ import annotations

import json

from whytrace.llm import complete_json, resolve_llm


CORRELATION_SYSTEM = """
You are the Correlation Analyst agent in WhyTrace, a digital forensics system.

Independently analyze the supplied detections, activity chains, and events.
Identify the likely sequence of activity, connections between data sources,
and alternative explanations or gaps in the evidence.

Rules:
- Use only supplied evidence.
- Never invent event IDs, users, hosts, IPs, or timestamps.
- Reference actual event IDs for every major conclusion.
- Distinguish observed facts from hypotheses.
- Flag missing evidence and alternative explanations.

Return JSON with these keys:
sequence: array of objects with step, explanation, event_ids
connections: array of objects with explanation, event_ids
gaps: array of strings
alternative_explanations: array of strings
confidence: low|medium|high
"""


VALIDATOR_SYSTEM = """
You are the Evidence Validator agent in WhyTrace.

Review a proposed investigation report against the supplied source events.
Check whether findings cite real event IDs and whether their explanations
are supported by those events. Flag overconfident conclusions, contradictions,
and claims that go beyond the available evidence.

Rules:
- Never invent evidence.
- A valid event ID alone does not prove a claim is supported.
- Do not reject a finding merely because evidence is incomplete.
- Clearly distinguish unsupported claims from reasonable hypotheses.
- Be conservative when judging evidence.

Return JSON with these keys:
approved_finding_ids: array of finding IDs
rejected_findings: array of objects with finding_id and reason
warnings: array of strings
overall_assessment: one sentence
"""


def run_correlation_agent(packet: dict) -> tuple[dict, str]:
    """Analyze relationships across detections, chains, and events."""
    if resolve_llm() is not None:
        try:
            result, model = complete_json(
                CORRELATION_SYSTEM,
                json.dumps(packet, indent=2),
            )
            return result, model
        except Exception:
            pass

    # Deterministic fallback when the model is unavailable.
    return {
        "sequence": [
            {
                "step": index + 1,
                "explanation": detection.get("title", "Detected activity"),
                "event_ids": detection.get("event_ids", []),
            }
            for index, detection in enumerate(packet.get("detections", []))
        ],
        "connections": [
            {
                "explanation": chain.get("title", "Related activity"),
                "event_ids": chain.get("event_ids", []),
            }
            for chain in packet.get("chains", [])
        ],
        "gaps": ["Model-based cross-source analysis was unavailable."],
        "alternative_explanations": [],
        "confidence": "medium",
    }, "rules-only-correlation"


def run_validation_agent(
    packet: dict,
    proposed_report: dict,
) -> tuple[dict, str]:
    """Critique a proposed report and check its evidence references."""
    validation_input = {
        "source_events": packet.get("events", []),
        "proposed_report": proposed_report,
    }

    if resolve_llm() is not None:
        try:
            result, model = complete_json(
                VALIDATOR_SYSTEM,
                json.dumps(validation_input, indent=2),
            )
            return result, model
        except Exception:
            pass

    # Safe fallback: approve only findings with existing cited event IDs.
    valid_event_ids = {
        event.get("id")
        for event in packet.get("events", [])
        if event.get("id")
    }

    approved = []
    rejected = []

    for finding in proposed_report.get("findings", []):
        finding_id = finding.get("id", "")
        evidence = finding.get("evidence", [])
        cited_ids = {
            item.get("event_id")
            for item in evidence
            if isinstance(item, dict)
        }

        if cited_ids & valid_event_ids:
            approved.append(finding_id)
        else:
            rejected.append({
                "finding_id": finding_id,
                "reason": "No evidence citation matched the supplied events.",
            })

    return {
        "approved_finding_ids": approved,
        "rejected_findings": rejected,
        "warnings": [
            "Fallback validation checks citations, not the full meaning of claims."
        ],
        "overall_assessment": "Checked evidence references using deterministic rules.",
    }, "rules-only-validation"
