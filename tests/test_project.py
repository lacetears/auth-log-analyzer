import importlib.util, json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
security=module('security','cybersecurity/detect.py')

def events(): return [json.loads(r) for r in (ROOT/'cybersecurity/data/auth_events.jsonl').read_text().splitlines()]

def test_attack_and_benign():
    alerts=security.detect(events());assert [a['rule'] for a in alerts]==['repeated_login_failure','success_after_failures'];assert all(a['host']=='lab-linux' for a in alerts)

def test_out_of_order(): assert security.detect(events()[::-1])==security.detect(events())

def test_window_expiry():
    rows=events()[:5];rows[-1]['timestamp']='2026-01-15T09:20:00Z';assert security.detect(rows)==[]

def test_separate_hosts():
    rows=events()[:5];rows[-1]['host']='other';assert security.detect(rows)==[]

def test_timezone_required():
    rows=events()[:1];rows[0]['timestamp']='2026-01-15T09:00:00'
    with pytest.raises(ValueError):security.detect(rows)
