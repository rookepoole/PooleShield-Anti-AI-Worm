import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pooleshield import PooleShieldDetector, Event, demo_events


def test_demo_detects_high_risk_events():
    detector = PooleShieldDetector()
    results = detector.analyze(demo_events())
    assert len(results) == 6
    assert max(r.risk_score for r in results) > 0.25
    assert any("persistent_write" in r.matched_labels for r in results)
    assert any("fanout_anomaly" in r.matched_labels for r in results)


def test_benign_event_low_risk():
    e = Event.from_dict({
        "timestamp": "2026-06-28T12:00:00Z",
        "node_id": "agent-safe",
        "source": "chat",
        "trust": "trusted",
        "content": "Summarize this meeting note for me.",
        "inbound_from": ["user"],
        "outbound_to": [],
        "tool_calls": ["read_file"],
    })
    detector = PooleShieldDetector()
    r = detector.analyze([e])[0]
    assert r.level in {"NORMAL", "WATCH"}
    assert r.risk_score < 0.25
