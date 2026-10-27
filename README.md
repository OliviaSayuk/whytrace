# WhyTrace

An investigation agent for digital forensics analysts. It reads fragmented activity logs, connects related events, and writes an evidence-backed report that explains **why** each finding looks suspicious.

Built for Open Agent Hackathon 2026, Track 02: *The Agent That Can Explain Why*.

## What it does

Investigators do not need another chatbot over a SIEM dump. They need a chain of custody between a claim and the rows that support it.

1. **Ingest** separate sources that never lived in one table: identity, VPN/directory auth, endpoint process telemetry, file-server audit, proxy/flow.
2. **Detect** with explicit rules mapped to ATT&CK (spray-then-success, off-hours unseen IP, encoded PowerShell, recon burst, PsExec/admin$, sensitive file reads, staging, exfil, persistence, log clear).
3. **Correlate** hits that share a user and a four-hour window into one activity chain, then expand nearby events.
4. **Explain** each finding in investigator language. Every sentence is tied to event IDs. If a model is configured (Meterless / NVIDIA Nemotron / OpenAI-compatible), it writes the narrative; if not, the same evidence packet still produces a rules-backed report. Cited IDs that do not exist in the case are dropped.

The shipped case, **Night Shift**, is a coherent account-takeover against Northline Capital: after-hours VPN from `185.220.101.47`, encoded PowerShell on `LAPTOP-JM-14`, finance share theft, a 90MB upload to `lumen-drop.net`.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/generate_case.py
uvicorn whytrace.app:app --reload --port 8000
```

Open http://127.0.0.1:8000 and click **Investigate this case**.

Optional model keys go in `.env` (see `.env.example`). WhyTrace is usable without them.

## Layout

- `data/cases/night-shift/` — fragmented JSONL sources plus case metadata
- `whytrace/detectors.py` — why-rules (not opaque scores)
- `whytrace/correlate.py` — chain building
- `whytrace/investigate.py` — agent pipeline and citation sanitizer
- `frontend/` — investigator workbench: findings, timeline, evidence chips
