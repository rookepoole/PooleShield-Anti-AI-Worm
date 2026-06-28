import json
from pathlib import Path

from approval_queue import build_queue
from corpus_scanner import scan_and_report
from policy_gate import build_policy_report, decide_one, load_policy


def test_balanced_policy_audits_sensitive_normal_without_approval():
    policy = load_policy('policy_config.balanced.json')
    d = decide_one({
        'event_id': 'e-sensitive',
        'node_id': 'agent-sec',
        'source': 'chat',
        'risk_score': 0.07,
        'level': 'NORMAL',
        'labels': ['secret_interest', 'sensitive_access'],
        'recommended_actions': ['log_only'],
    }, policy)
    assert d.decision == 'ALLOW_LOG'
    assert 'sensitive_reference_audit_only' in d.reasons


def test_strict_policy_requires_approval_for_sensitive_normal():
    policy = load_policy('policy_config.strict.json')
    d = decide_one({
        'event_id': 'e-sensitive',
        'node_id': 'agent-sec',
        'source': 'chat',
        'risk_score': 0.07,
        'level': 'NORMAL',
        'labels': ['secret_interest', 'sensitive_access'],
        'recommended_actions': ['log_only'],
    }, policy)
    assert d.decision == 'REQUIRE_APPROVAL'


def test_cycle7_queue_from_fixture(tmp_path):
    fixture = Path('examples/corpus_scan_fixture')
    scan_report = tmp_path / 'scan.json'
    normalized = tmp_path / 'norm.jsonl'
    manifest = tmp_path / 'manifest.json'
    scan_and_report(
        paths=[str(fixture)],
        normalized_path=str(normalized),
        output_path=str(scan_report),
        csv_path=str(tmp_path / 'scan.csv'),
        manifest_path=str(manifest),
        manifest_md_path=str(tmp_path / 'manifest.md'),
    )
    policy = build_policy_report(
        str(scan_report),
        str(tmp_path / 'policy.json'),
        str(tmp_path / 'policy.csv'),
        str(tmp_path / 'policy.md'),
        policy_path='policy_config.balanced.json',
    )
    assert policy['summary']['by_decision'].get('ALLOW_LOG', 0) >= 1
    queue = build_queue(
        str(tmp_path / 'policy.json'),
        str(tmp_path / 'queue.json'),
        str(tmp_path / 'queue.csv'),
        str(tmp_path / 'queue.md'),
        normalized_path=str(normalized),
        manifest_path=str(manifest),
    )
    assert queue['summary']['total_items'] >= 2
    assert all(item['decision'] != 'ALLOW' for item in queue['items'])
    assert any(item['priority'] == 'P2' for item in queue['items'])
    assert (tmp_path / 'queue.md').exists()


def test_scan_report_preserves_source_paths(tmp_path):
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
    data = json.loads(scan_report.read_text(encoding='utf-8'))
    assert all('source_path' in e for e in data['events'])
    assert any(e['source_path'] for e in data['events'])
