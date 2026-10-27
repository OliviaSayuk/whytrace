from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from whytrace.models import Chain, Detection, Event


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def correlate(events: list[Event], detections: list[Detection]) -> list[Chain]:
    """Group detections that share a user and sit in a four-hour window."""
    by_id = {e.id: e for e in events}
    buckets: dict[str, list[Detection]] = defaultdict(list)
    for det in detections:
        users = det.entities.get("user") or ["unknown"]
        buckets[users[0] or "unknown"].append(det)

    chains: list[Chain] = []
    for user, dets in buckets.items():
        dets = sorted(dets, key=lambda d: min(_parse(by_id[i].ts) for i in d.event_ids if i in by_id))
        current: list[Detection] = []
        window_end: datetime | None = None
        for det in dets:
            start = min(_parse(by_id[i].ts) for i in det.event_ids if i in by_id)
            if current and window_end and start > window_end:
                chains.append(_make_chain(user, current, by_id, len(chains) + 1))
                current = []
            current.append(det)
            last = max(_parse(by_id[i].ts) for i in det.event_ids if i in by_id)
            window_end = last + timedelta(hours=4)
        if current:
            chains.append(_make_chain(user, current, by_id, len(chains) + 1))

    chains.sort(key=lambda c: c.score, reverse=True)
    return chains


def related_events(seed_ids: list[str], events: list[Event], minutes: int = 90) -> list[str]:
    """Expand a detection's events to nearby same-user/host activity."""
    by_id = {e.id: e for e in events}
    seeds = [by_id[i] for i in seed_ids if i in by_id]
    if not seeds:
        return []
    users = {e.user for e in seeds if e.user}
    hosts = {e.host for e in seeds if e.host}
    pids = {e.pid for e in seeds if e.pid} | {e.ppid for e in seeds if e.ppid}
    t0 = min(_parse(e.ts) for e in seeds) - timedelta(minutes=15)
    t1 = max(_parse(e.ts) for e in seeds) + timedelta(minutes=minutes)
    related: list[str] = []
    for event in events:
        ts = _parse(event.ts)
        if ts < t0 or ts > t1:
            continue
        if event.source == "identity":
            continue
        same_actor = (event.user and event.user in users) or (event.host and event.host in hosts)
        same_proc = (event.pid and event.pid in pids) or (event.ppid and event.ppid in pids)
        if same_actor or same_proc:
            related.append(event.id)
    return related


def _make_chain(user: str, dets: list[Detection], by_id: dict[str, Event], n: int) -> Chain:
    event_ids: list[str] = []
    seen: set[str] = set()
    for det in dets:
        for eid in det.event_ids:
            if eid not in seen:
                seen.add(eid)
                event_ids.append(eid)
    stamps = [_parse(by_id[i].ts) for i in event_ids if i in by_id]
    hosts = sorted({by_id[i].host for i in event_ids if i in by_id and by_id[i].host})
    title = f"{user} activity chain" if user != "unknown" else "Unattributed chain"
    return Chain(
        id=f"chain-{n}",
        title=title,
        user=None if user == "unknown" else user,
        hosts=hosts,
        start_ts=min(stamps).strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_ts=max(stamps).strftime("%Y-%m-%dT%H:%M:%SZ"),
        detection_ids=[d.id for d in dets],
        event_ids=event_ids,
        score=round(min(1.0, sum(d.score for d in dets) / 3), 3),
    )
