import csv
import json
from pathlib import Path

from approval_queue import build_queue
from corpus_scanner import scan_and_report
from policy_gate import build_policy_report
from review_ledger import (
    apply_review_ledger,
    build_review_template,
    write_demo_decisions_from_queue,
)


def _build_cycle7_inputs(tmp_path):
    fixture = Path('examples/corpus_scan_fixture')
    scan_report = tmp_path / 'scan.json'
    normalized = tmp_path / 'norm.jsonl'
    manifest = tmp_path / 'manifest.json'
    policy_report = tmp_path / 'policy.json'
    queue_report = tmp_path / 'queue.json'
    scan_and_report(
        paths=[str(fixture)],
        normalized_path=str(normalized),
        output_path=str(scan_report),
        csv_path=str(tmp_path / 'scan.csv'),
        manifest_path=str(manifest),
        manifest_md_path=str(tmp_path / 'manifest.md'),
    )
    build_policy_report(
        str(scan_report),
        str(policy_report),
        str(tmp_path / 'policy.csv'),
        str(tmp_path / 'policy.md'),
        policy_path='policy_config.balanced.json',
    )
    queue = build_queue(
        str(policy_report),
        str(queue_report),
        str(tmp_path / 'queue.csv'),
        str(tmp_path / 'queue.md'),
        normalized_path=str(normalized),
        manifest_path=str(manifest),
    )
    return policy_report, queue_report, queue


def test_approval_queue_has_stable_review_keys(tmp_path):
    _, _, queue = _build_cycle7_inputs(tmp_path)
    assert queue['items']
    keys = [item['review_key'] for item in queue['items']]
    assert all(keys)
    assert len(keys) == len(set(keys))
    assert all(item['review_id'].startswith('PSR-') for item in queue['items'])


def test_review_template_outputs_pending_rows(tmp_path):
    _, queue_report, queue = _build_cycle7_inputs(tmp_path)
    template = build_review_template(
        str(queue_report),
        str(tmp_path / 'ledger_template.csv'),
        str(tmp_path / 'ledger_template.json'),
        str(tmp_path / 'ledger_template.md'),
    )
    assert template['summary']['total_rows'] == queue['summary']['total_items']
    assert all(row['operator_decision'] == 'PENDING' for row in template['rows'])
    assert (tmp_path / 'ledger_template.csv').exists()


def test_demo_review_ledger_applies_allow_and_deny_lists(tmp_path):
    policy_report, queue_report, _ = _build_cycle7_inputs(tmp_path)
    demo_csv = tmp_path / 'review_demo.csv'
    write_demo_decisions_from_queue(str(queue_report), str(demo_csv))
    report = apply_review_ledger(
        str(policy_report),
        str(queue_report),
        str(demo_csv),
        str(tmp_path / 'effective.json'),
        str(tmp_path / 'effective.csv'),
        str(tmp_path / 'effective.md'),
        str(tmp_path / 'allowlist.json'),
        str(tmp_path / 'denylist.json'),
    )
    assert report['summary']['applied_ledger_rows'] >= 3
    assert report['summary']['allowlist_entries'] >= 1
    assert report['summary']['denylist_entries'] >= 1
    decisions = report['summary']['by_effective_decision']
    assert 'ALLOW_LOG' in decisions
    assert any(k in decisions for k in ['BLOCK', 'QUARANTINE'])


def test_manual_approve_once_changes_one_item_to_allow_log(tmp_path):
    policy_report, queue_report, queue = _build_cycle7_inputs(tmp_path)
    first = queue['items'][0]
    ledger_csv = tmp_path / 'manual_ledger.csv'
    fields = ['review_key', 'review_id', 'event_id', 'operator_decision', 'scope', 'operator', 'reason', 'expires_at', 'notes']
    with ledger_csv.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerow({
            'review_key': first['review_key'],
            'review_id': first['review_id'],
            'event_id': first['event_id'],
            'operator_decision': 'APPROVE_ONCE',
            'scope': 'CONTENT_HASH',
            'operator': 'unit_test',
            'reason': 'approved for this test only',
            'expires_at': '',
            'notes': '',
        })
    report = apply_review_ledger(
        str(policy_report),
        str(queue_report),
        str(ledger_csv),
        str(tmp_path / 'effective.json'),
        str(tmp_path / 'effective.csv'),
        str(tmp_path / 'effective.md'),
        str(tmp_path / 'allowlist.json'),
        str(tmp_path / 'denylist.json'),
    )
    matched = [row for row in report['decisions'] if row.get('review_key') == first['review_key']]
    assert matched
    assert matched[0]['effective_decision'] == 'ALLOW_LOG'
    assert matched[0]['ledger_status'] == 'applied'
