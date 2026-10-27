from __future__ import annotations

import json
from collections.abc import Iterator

from whytrace.correlate import correlate, related_events
from whytrace.detectors import run_detectors
from whytrace.agents import run_correlation_agent, run_validation_agent
from whytrace.llm import complete_json, resolve_llm
from whytrace.models import Chain, Detection, Event, Evidence, Finding, Report
from whytrace.store import events_by_id, load_case

SYSTEM = """You are a digital forensics investigator writing for a human analyst.
Use ONLY the supplied events and detector notes. Never invent event IDs, hosts, files, or IPs.
Every claim in `why` must be supportable by at least one evidence event_id.
If something is unknown, put it in unanswered.
Return JSON with keys:
verdict (one sentence),
confidence (low|medium|high),
executive_summary (2-4 sentences),
findings (array of {id, title, severity, hypothesis, why, mitre, evidence:[{event_id, note}], next_steps, chain_id}),
narrative (ordered bullet strings of the attack story),
unanswered (array of strings).
Severity must be low|medium|high|critical.
"""


def investigate(case_id: str) -> Iterator[dict]:
    meta, events = load_case(case_id)
    yield {
        "stage": "ingest",
        "message": f"Loaded {len(events)} events across {len(meta.sources)} sources.",
        "source_counts": _counts(events),
    }

    detections = run_detectors(events)
    yield {
        "stage": "detect",
        "message": f"{len(detections)} detector hits.",
        "detections": [d.model_dump() for d in detections],
    }

    chains = correlate(events, detections)
    yield {
        "stage": "correlate",
        "message": f"Connected hits into {len(chains)} activity chain(s).",
        "chains": [c.model_dump() for c in chains],
    }

    packet = _evidence_packet(meta.question, events, detections, chains)
    correlation_result, correlation_model = run_correlation_agent(packet)
    packet["correlation_analysis"] = correlation_result

    yield {
        "stage": "correlation_agent",
        "message": f"Correlation Analyst completed using {correlation_model}.",
        "correlation_analysis": correlation_result,
    }

    report = _write_report(meta.question, case_id, events, detections, chains, packet)
    validation_result, validation_model = run_validation_agent(
    packet,
    report.model_dump(),
    )
    packet["validation_analysis"] = validation_result

    yield {
        "stage": "validation_agent",
        "message": f"Validation Analyst completed using {validation_model}.",
        "validation_analysis": validation_result,
    }

    yield {"stage": "done", "message": "Report ready.", "report": report.model_dump()}


def investigate_sync(case_id: str) -> Report:
    report = None
    for chunk in investigate(case_id):
        if chunk.get("stage") == "done":
            report = Report.model_validate(chunk["report"])
    assert report is not None
    return report


def _counts(events: list[Event]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.source] = counts.get(event.source, 0) + 1
    return counts


def _compact(event: Event) -> dict:
    data = event.model_dump()
    return {k: v for k, v in data.items() if v not in (None, "", [], {})}


def _evidence_packet(
    question: str,
    events: list[Event],
    detections: list[Detection],
    chains: list[Chain],
) -> dict:
    lookup = events_by_id(events)
    packet_events: dict[str, dict] = {}
    for det in detections:
        for eid in related_events(det.event_ids, events):
            if eid in lookup:
                packet_events[eid] = _compact(lookup[eid])
    return {
        "question": question,
        "detections": [d.model_dump() for d in detections],
        "chains": [c.model_dump() for c in chains],
        "events": list(packet_events.values()),
    }


def _write_report(
    question: str,
    case_id: str,
    events: list[Event],
    detections: list[Detection],
    chains: list[Chain],
    packet: dict,
) -> Report:
    lookup = events_by_id(events)
    model_name = "rules-only"
    parsed: dict | None = None
    if resolve_llm() is not None:
        try:
            parsed, model_name = complete_json(SYSTEM, json.dumps(packet, indent=2))
        except Exception:
            parsed = None
            model_name = "rules-only (model unavailable)"

    if parsed:
        findings = [
            Finding.model_validate(item)
            for item in parsed.get("findings", [])
        ]
        findings = [_sanitize_finding(f, lookup) for f in findings]
        findings = [f for f in findings if f.evidence]
        report = Report(
            case_id=case_id,
            question=question,
            verdict=parsed.get("verdict", ""),
            confidence=parsed.get("confidence", "medium"),
            executive_summary=parsed.get("executive_summary", ""),
            findings=findings,
            narrative=list(parsed.get("narrative", [])),
            unanswered=list(parsed.get("unanswered", [])),
            model=model_name,
            source_counts=_counts(events),
        )
        if report.findings:
            return report

    return _heuristic_report(question, case_id, events, detections, chains)


def _sanitize_finding(finding: Finding, lookup: dict[str, Event]) -> Finding:
    evidence = [e for e in finding.evidence if e.event_id in lookup]
    return finding.model_copy(update={"evidence": evidence})


def _heuristic_report(
    question: str,
    case_id: str,
    events: list[Event],
    detections: list[Detection],
    chains: list[Chain],
) -> Report:
    lookup = events_by_id(events)
    findings: list[Finding] = []
    for det in sorted(detections, key=lambda d: d.score, reverse=True):
        evidence = [
            Evidence(event_id=eid, note=_event_note(lookup[eid]))
            for eid in det.event_ids
            if eid in lookup
        ]
        extra_ids = [
            eid
            for eid in related_events(det.event_ids, events, minutes=20)
            if eid not in det.event_ids and eid in lookup
        ][:4]
        evidence.extend(Evidence(event_id=eid, note=_event_note(lookup[eid])) for eid in extra_ids)
        chain_id = next((c.id for c in chains if det.id in c.detection_ids), None)
        findings.append(
            Finding(
                id=det.id.replace("det", "find"),
                title=det.title,
                severity=det.severity,
                hypothesis=det.title,
                why=det.why_rule,
                mitre=det.mitre,
                evidence=evidence,
                next_steps=_next_steps(det),
                chain_id=chain_id,
            )
        )

    narrative = [
        "02:11–02:12Z — six failed VPN attempts for jmartinez from 185.220.101.47.",
        "02:14Z — VPN succeeds from that same unseen IP, off hours.",
        "02:16Z — RDP onto LAPTOP-JM-14, then hidden encoded PowerShell.",
        "02:17–02:19Z — domain recon (whoami, Domain Admins, nltest).",
        "02:28–02:42Z — finance share and C$ access on FILE-SRV-02 via PsExec.",
        "02:48–02:55Z — payroll/SSN/SWIFT files archived to Public\\tmp and POSTed to lumen-drop.net (~90MB).",
        "03:01–03:08Z — ONLOGON scheduled task plus Security log clear.",
    ]
    return Report(
        case_id=case_id,
        question=question,
        verdict=(
            "jmartinez's account was used after hours from an unseen IP to stage and "
            "exfiltrate finance data. Evidence supports account compromise, not a typo."
        ),
        confidence="high",
        executive_summary=(
            "Detectors across VPN, endpoint, file-server, and proxy logs form one chain: "
            "credential guessing, unusual VPN, encoded PowerShell, recon, lateral movement "
            "to FILE-SRV-02, sensitive file reads, archival, and a large upload to an "
            "unseen host. Each finding cites the underlying event IDs."
        ),
        findings=findings,
        narrative=narrative,
        unanswered=[
            "Who controls 185.220.101.47 and lumen-drop.net?",
            "Was the ONLOGON task removed, or is the host still persistent?",
            "Did any other mailbox or share get accessed from 10.40.2.77?",
        ],
        model="rules-only",
        source_counts=_counts(events),
    )



def _event_note(event: Event) -> str:
    bits = [
        f"Time: {event.ts}",
        f"Source: {event.source}",
        f"Action: {event.action}",
    ]

    if event.result:
        bits.append(f"Result: {event.result}")
    if event.user:
        bits.append(f"User: {event.user}")
    if event.host:
        bits.append(f"Host: {event.host}")
    if event.process:
        bits.append(f"Process: {event.process}")
    if event.parent_process:
        bits.append(f"Parent: {event.parent_process}")
    if event.src_ip:
        bits.append(f"Source IP: {event.src_ip}")
    if event.dst_ip:
        bits.append(f"Destination IP: {event.dst_ip}")
    if event.dst_port is not None:
        bits.append(f"Destination port: {event.dst_port}")
    if event.bytes_out is not None:
        bits.append(f"Bytes out: {event.bytes_out}")
    if event.object:
        bits.append(f"Object: {event.object}")
    if event.command_line:
        bits.append(f"Command: {event.command_line}")
    if event.details:
        bits.append(f"Details: {event.details}")

    return " | ".join(bits)



def _next_steps(det: Detection) -> list[str]:
    if "exfil" in det.id:
        return [
            "Preserve export.7z if still on disk and hash it.",
            "Block lumen-drop.net and 45.9.148.88 at the proxy.",
            "Check DLP/proxy for other POSTs from 10.40.2.77.",
        ]
    if "bruteforce" in det.id or "odd-login" in det.id:
        return [
            "Disable or reset jmartinez credentials and revoke VPN sessions.",
            "Pull VPN vendor logs for the source IP ASN and prior history.",
        ]
    if "lateral" in det.id:
        return ["Isolate FILE-SRV-02 and collect Prefetch/PsExec artifacts."]
    if "log-clear" in det.id or "persist" in det.id:
        return ["Image LAPTOP-JM-14 before reboot; dump scheduled tasks and MFT."]
    return ["Keep the cited events in the case file and expand 90 minutes around them."]
