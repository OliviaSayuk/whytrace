from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from whytrace.investigate import investigate
from whytrace.llm import resolve_llm
from whytrace.store import load_case, list_cases

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"

app = FastAPI(title="WhyTrace", version="0.1.0")
app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


@app.get("/api/health")
def health() -> dict:
    llm = resolve_llm()
    return {
        "ok": True,
        "llm": None if llm is None else {"name": llm.name, "model": llm.model},
    }


@app.get("/api/cases")
def cases() -> list[dict]:
    return [c.model_dump() for c in list_cases()]


@app.get("/api/cases/{case_id}")
def case_detail(case_id: str) -> dict:
    try:
        meta, events = load_case(case_id)
    except FileNotFoundError as exc:
        raise HTTPException(404, "unknown case") from exc
    return {
        "case": meta.model_dump(),
        "events": [e.model_dump() for e in events],
        "source_counts": _counts(events),
    }


@app.post("/api/cases/{case_id}/investigate")
def run_investigation(case_id: str) -> StreamingResponse:
    try:
        load_case(case_id)
    except FileNotFoundError as exc:
        raise HTTPException(404, "unknown case") from exc

    def stream():
        for chunk in investigate(case_id):
            yield json.dumps(chunk) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


def _counts(events) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.source] = counts.get(event.source, 0) + 1
    return counts
