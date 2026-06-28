import json
from pathlib import Path

from corpus_scanner import normalize_scan_paths, scan_and_report


def test_corpus_fixture_normalizes(tmp_path):
    fixture = Path('examples/corpus_scan_fixture')
    normalized_path = tmp_path / 'norm.jsonl'
    events, path_map, skipped = normalize_scan_paths([str(fixture)], normalized_path=str(normalized_path))
    assert len(events) >= 4
    assert normalized_path.exists()
    assert isinstance(path_map, dict)


def test_corpus_scan_report_outputs(tmp_path):
    fixture = Path('examples/corpus_scan_fixture')
    summary = scan_and_report(
        paths=[str(fixture)],
        normalized_path=str(tmp_path / 'norm.jsonl'),
        output_path=str(tmp_path / 'report.json'),
        csv_path=str(tmp_path / 'report.csv'),
        manifest_path=str(tmp_path / 'manifest.json'),
        manifest_md_path=str(tmp_path / 'manifest.md'),
    )
    assert summary['summary']['total_events'] >= 4
    assert summary['manifest_summary']['total_manifest_entries'] >= 1
    manifest = json.loads((tmp_path / 'manifest.json').read_text(encoding='utf-8'))
    assert any(e['level'] in {'WATCH','RESTRICT','QUARANTINE','ISOLATE'} for e in manifest['entries'])
