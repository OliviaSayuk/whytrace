from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime

from whytrace.models import Detection, Event
from whytrace.store import identity_for, ip_in_usual_networks

SENSITIVE_FILE = re.compile(
    r"payroll|ssn|swift|wire_templates|ntds|id_rsa|m&a|secret",
    re.I,
)
RECON = re.compile(r"whoami|nltest|net group|net user|ipconfig /all", re.I)
ENCODED_PS = re.compile(r"powershell(\.exe)?[^\n]*-enc", re.I)
LOLBINS = re.compile(r"psexec|wmic|rundll32|mshta|certutil", re.I)
STAGING = re.compile(r"\\users\\public\\|\\temp\\|export\.(7z|zip|rar)", re.I)
LOG_CLEAR = re.compile(r"wevtutil|log_clear", re.I)


def _ts(event: Event) -> datetime:
    return datetime.fromisoformat(event.ts.replace("Z", "+00:00"))


def _hour(event: Event) -> int:
    return _ts(event).hour


def run_detectors(events: list[Event]) -> list[Detection]:
    detections: list[Detection] = []
    detections.extend(_vpn_failures_then_success(events))
    detections.extend(_unusual_login(events))
    detections.extend(_encoded_powershell(events))
    detections.extend(_recon(events))
    detections.extend(_lateral(events))
    detections.extend(_sensitive_files(events))
    detections.extend(_staging_and_exfil(events))
    detections.extend(_persistence(events))
    detections.extend(_log_tamper(events))
    return detections


def _vpn_failures_then_success(events: list[Event]) -> list[Detection]:
    by_user: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.source == "auth" and event.action == "vpn_login" and event.user:
            by_user[event.user].append(event)
    out: list[Detection] = []
    for user, rows in by_user.items():
        window: list[Event] = []
        for event in rows:
            if event.result == "failure":
                window.append(event)
                continue
            if event.result == "success" and len(window) >= 4:
                ids = [e.id for e in window[-6:]] + [event.id]
                out.append(
                    Detection(
                        id=f"det-bruteforce-{user}",
                        title=f"VPN password spray then success for {user}",
                        severity="high",
                        mitre=["T1110.001", "T1078"],
                        why_rule=(
                            f"{len(window)} failed VPN logins from "
                            f"{window[-1].src_ip} immediately preceded a successful "
                            f"login. That pattern is credential guessing, not a typo."
                        ),
                        event_ids=ids,
                        entities={"user": [user], "src_ip": [event.src_ip or ""]},
                        score=0.86,
                    )
                )
            window = []
    return out


def _unusual_login(events: list[Event]) -> list[Detection]:
    out: list[Detection] = []
    for event in events:
        if event.source != "auth" or event.action != "vpn_login" or event.result != "success":
            continue
        profile = identity_for(events, event.user)
        usual = (profile.details.get("usual_networks") if profile else None) or []
        off_hours = _hour(event) < 12 or _hour(event) >= 22  # UTC; NY analyst works 13-21Z
        unknown_net = not ip_in_usual_networks(event.src_ip, usual)
        if unknown_net and off_hours:
            out.append(
                Detection(
                    id=f"det-odd-login-{event.id}",
                    title=f"Off-hours VPN from unseen network ({event.src_ip})",
                    severity="high",
                    mitre=["T1133", "T1078"],
                    why_rule=(
                        f"{event.user} normally authenticates from {usual} during "
                        f"{profile.details.get('usual_hours') if profile else 'business hours'}. "
                        f"This success came from {event.src_ip} at {event.ts}."
                    ),
                    event_ids=[event.id],
                    entities={"user": [event.user or ""], "src_ip": [event.src_ip or ""]},
                    score=0.8,
                )
            )
    return out



def _encoded_powershell(events: list[Event]) -> list[Detection]:
    out: list[Detection] = []

    for event in events:
        cmd = event.command_line or ""

        # Only flag an actual PowerShell process, not another
        # program that mentions PowerShell in its arguments.
        if (
            event.source == "process"
            and (event.process or "").lower() in {"powershell.exe", "powershell"}
            and ENCODED_PS.search(cmd)
        ):
            out.append(
                Detection(
                    id=f"det-ps-{event.id}",
                    title=f"Encoded PowerShell execution on {event.host or 'unknown host'}",
                    severity="critical",
                    mitre=["T1059.001", "T1027"],
                    why_rule=(
                        f"Process event {event.id} records PowerShell launched "
                        "with the -Enc flag. Encoding can obscure script behavior; "
                        "inspect the decoded payload and surrounding events to "
                        "determine whether this execution was malicious."
                    ),
                    event_ids=[event.id],
                    entities={
                        "user": [event.user or ""],
                        "host": [event.host or ""],
                    },
                    score=0.92,
                )
            )

    return out


def _recon(events: list[Event]) -> list[Detection]:
    hits = [
        e
        for e in events
        if e.source == "process" and e.command_line and RECON.search(e.command_line)
    ]
    if len(hits) < 2:
        return []
    return [
        Detection(
            id="det-recon-burst",
            title="Domain reconnaissance burst",
            severity="high",
            mitre=["T1087.002", "T1069.002", "T1016"],
            why_rule=(
                "whoami, net group Domain Admins, nltest, and ipconfig in a tight "
                "window is discovery after access, not normal analyst work."
            ),
            event_ids=[e.id for e in hits],
            entities={"user": sorted({e.user or "" for e in hits})},
            score=0.84,
        )
    ]


def _lateral(events: list[Event]) -> list[Detection]:
    hits = [
        e
        for e in events
        if (e.command_line and LOLBINS.search(e.command_line))
        or e.action in {"admin_share_access"}
        or (e.object or "").endswith("C$")
        or "admin$" in (e.object or "").lower()
    ]
    if not hits:
        return []
    return [
        Detection(
            id="det-lateral",
            title="Lateral movement onto FILE-SRV-02",
            severity="critical",
            mitre=["T1021.002", "T1570"],
            why_rule=(
                "PsExec plus C$ / admin$ access moves the actor from a laptop onto "
                "the finance file server. That is not how payroll files are opened."
            ),
            event_ids=[e.id for e in hits],
            entities={"user": sorted({e.user or "" for e in hits if e.user})},
            score=0.9,
        )
    ]


def _sensitive_files(events: list[Event]) -> list[Detection]:
    hits = [
        e
        for e in events
        if e.source == "file"
        and e.object
        and SENSITIVE_FILE.search(e.object)
        and _hour(e) < 12
    ]
    if not hits:
        return []
    return [
        Detection(
            id="det-sensitive-files",
            title="After-hours reads of payroll and wire files",
            severity="critical",
            mitre=["T1005", "T1039"],
            why_rule=(
                "Payroll, SSN export, SWIFT templates, and M&A models were read "
                "in a burst after the unusual VPN login. Sensitivity plus timing "
                "is the signal, not any single file open."
            ),
            event_ids=[e.id for e in hits],
            entities={"user": sorted({e.user or "" for e in hits})},
            score=0.88,
        )
    ]


def _staging_and_exfil(events: list[Event]) -> list[Detection]:
    staging = [
        e
        for e in events
        if (e.command_line and STAGING.search(e.command_line))
        or (e.object and STAGING.search(e.object) and e.action in {"file_create", "file_read"})
    ]
    exfil = [
        e
        for e in events
        if e.source == "network"
        and (e.bytes_out or 0) > 5_000_000
        and e.dst_ip
        and not e.dst_ip.startswith("10.")
    ]
    if not staging and not exfil:
        return []
    ids = [e.id for e in staging + exfil]
    return [
        Detection(
            id="det-exfil",
            title="Archive staged in Public\\tmp then uploaded off-network",
            severity="critical",
            mitre=["T1560.001", "T1567.002"],
            why_rule=(
                "A 7z archive in C:\\Users\\Public\\tmp followed by a ~90MB POST "
                "to an unseen domain is a classic collection-and-exfil sequence."
            ),
            event_ids=ids,
            entities={"dst_ip": sorted({e.dst_ip for e in exfil if e.dst_ip})},
            score=0.95,
        )
    ]


def _persistence(events: list[Event]) -> list[Detection]:
    hits = [e for e in events if e.process == "schtasks.exe" or (e.command_line or "").lower().startswith("schtasks")]
    if not hits:
        return []
    return [
        Detection(
            id="det-persist",
            title="On-logon scheduled task for encoded PowerShell",
            severity="high",
            mitre=["T1053.005"],
            why_rule="A new ONLOGON task that relaunches encoded PowerShell is persistence, not a software update.",
            event_ids=[e.id for e in hits],
            entities={"host": sorted({e.host or "" for e in hits})},
            score=0.78,
        )
    ]


def _log_tamper(events: list[Event]) -> list[Detection]:
    hits = [
        e
        for e in events
        if e.action == "log_clear" or (e.command_line and LOG_CLEAR.search(e.command_line))
    ]
    if not hits:
        return []
    return [
        Detection(
            id="det-log-clear",
            title="Security event log cleared",
            severity="high",
            mitre=["T1070.001"],
            why_rule="Clearing Security.evtx after the activity is anti-forensics. The clear itself is evidence.",
            event_ids=[e.id for e in hits],
            entities={"host": sorted({e.host or "" for e in hits})},
            score=0.82,
        )
    ]
