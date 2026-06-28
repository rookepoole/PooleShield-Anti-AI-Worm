import json
from pathlib import Path

from corpus_scanner import scan_and_report
from policy_gate import build_policy_report, decide_one, DEFAULT_POLICY


def test_decide_normal_allows():
    d = decide_one({
        'event_id': 'e1', 'node_id': 'agent-safe', 'source': 'chat',
        'risk_score': 0.01, 'level': 'NORMAL', 'labels': [], 'recommended_actions': []
    }, DEFAULT_POLICY)
    assert d.decision == 'ALLOW'


def test_decide_restrict_blocks():
    d = decide_one({
        'event_id': 'e2', 'node_id': 'agent-risk', 'source': 'email',
        'risk_score': 0.46, 'level': 'RESTRICT',
        'labels': ['dangerous_tool_call', 'persistent_write'],
        'recommended_actions': ['block_auto_send_forward_delete_execute']
    }, DEFAULT_POLICY)
    assert d.decision in {'BLOCK', 'QUARANTINE'}
    assert 'block_autonomous_dangerous_action' in d.containment_actions or 'block_auto_send_forward_delete_execute' in d.containment_actions


def test_decide_worm_geometry_quarantines_watch_candidate():
    d = decide_one({
        'event_id': 'e3', 'node_id': 'agent-fanout', 'source': 'tool',
        'risk_score': 0.32, 'level': 'WATCH',
        'labels': ['worm_geometry', 'fanout_anomaly'],
        'recommended_actions': ['temporarily_limit_outbound_fanout']
    }, DEFAULT_POLICY)
    assert d.decision == 'QUARANTINE'


def test_policy_report_from_scan(tmp_path):
    fixture = Path('examples/corpus_scan_fixture')
    scan_report = tmp_path / 'scan.json'
    scan_and_report(
        paths=[str(fixture)],
        normalized_path=str(tmp_path / 'norm.jsonl'),
        output_path=str(scan_report),
        csv_path=str(tmp_path / 'scan.csv'),
        manifest_path=str(tmp_path / 'manifest.json'),
        manifest_md_path=str(tmp_path / 'manifest.md'),
    )
    policy_report = build_policy_report(
        str(scan_report),
        str(tmp_path / 'policy.json'),
        str(tmp_path / 'policy.csv'),
        str(tmp_path / 'policy.md'),
    )
    assert policy_report['summary']['total_decisions'] >= 4
    assert any(d['decision'] in {'REQUIRE_APPROVAL', 'BLOCK', 'QUARANTINE'} for d in policy_report['decisions'])
    assert (tmp_path / 'policy.json').exists()
