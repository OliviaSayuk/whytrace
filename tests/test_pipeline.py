from whytrace.investigate import investigate_sync
from whytrace.store import load_case


def test_night_shift_cites_real_events():
    meta, events = load_case("night-shift")
    ids = {e.id for e in events}
    report = investigate_sync(meta.id)
    assert report.findings
    assert report.confidence == "high"
    for finding in report.findings:
        assert finding.evidence
        for item in finding.evidence:
            assert item.event_id in ids
    cited = {item.event_id for f in report.findings for item in f.evidence}
    assert "auth-014" in cited
    assert "proc-011" in cited
    assert "net-015" in cited
