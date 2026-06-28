import json
from pathlib import Path

from file_av_rules import validate_rule_pack_file, load_rule_pack
from file_antivirus import run_file_av_scan


def test_rule_pack_validate_default():
    result = validate_rule_pack_file('examples/rule_packs/file_av_rules.default.json')
    assert result['valid'] is True
    assert result['rule_pack']['rules_enabled'] >= 1


def test_rule_pack_adds_label_and_risk(tmp_path):
    fixture = tmp_path / 'invoice.ps1'
    fixture.write_text('Write-Host hello\n', encoding='utf-8')
    rule_pack = tmp_path / 'rules.json'
    rule_pack.write_text(json.dumps({
        'version': 'test',
        'rules': [{
            'id': 'invoice_script',
            'enabled': True,
            'type': 'filename_regex',
            'pattern': '(?i)invoice.*\\.ps1$',
            'label': 'unit_rule_invoice_script',
            'risk_delta': 0.2,
            'reason': 'unit-test rule hit'
        }]
    }), encoding='utf-8')
    out = tmp_path / 'out'
    run_file_av_scan([str(fixture)], output_dir=str(out), clean_output=True, rule_pack=str(rule_pack))
    report = json.loads((out / 'file_av_report.json').read_text(encoding='utf-8'))
    item = report['items'][0]
    assert 'unit_rule_invoice_script' in item['labels']
    assert any('unit-test rule hit' in r for r in item['reasons'])
    assert report['settings']['rule_pack']['enabled'] is True


def test_missing_rule_pack_error(tmp_path):
    missing = tmp_path / 'missing.json'
    try:
        load_rule_pack(str(missing))
    except FileNotFoundError as exc:
        assert 'rule pack not found' in str(exc)
    else:
        raise AssertionError('expected FileNotFoundError')
