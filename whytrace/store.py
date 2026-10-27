from __future__ import annotations

import json
from functools import lru_cache
from ipaddress import ip_address, ip_network
from pathlib import Path

from whytrace.models import CaseMeta, Event

DATA_ROOT = Path(__file__).resolve().parents[1] / "data" / "cases"


def _load_jsonl(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            events.append(Event.model_validate(json.loads(line)))
    return events


@lru_cache(maxsize=8)
def load_case(case_id: str) -> tuple[CaseMeta, list[Event]]:
    case_dir = DATA_ROOT / case_id
    meta = CaseMeta.model_validate_json((case_dir / "case.json").read_text(encoding="utf-8"))
    events: list[Event] = []
    for source in meta.sources:
        events.extend(_load_jsonl(case_dir / source.path))
    events.sort(key=lambda e: (e.ts, e.id))
    return meta, events


def list_cases() -> list[CaseMeta]:
    cases = []
    for path in sorted(DATA_ROOT.glob("*/case.json")):
        cases.append(CaseMeta.model_validate_json(path.read_text(encoding="utf-8")))
    return cases


def events_by_id(events: list[Event]) -> dict[str, Event]:
    return {e.id: e for e in events}


def identity_for(events: list[Event], user: str | None) -> Event | None:
    if not user:
        return None
    for event in events:
        if event.source == "identity" and event.user == user:
            return event
    return None


def ip_in_usual_networks(ip: str | None, networks: list[str] | None) -> bool:
    if not ip or not networks:
        return False
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False
