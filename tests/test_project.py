import importlib.util, json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


security = module("security", "cybersecurity/detect.py")


def events():
    return [
        json.loads(r)
        for r in (ROOT / "cybersecurity/data/auth_events.jsonl")
        .read_text()
        .splitlines()
    ]


def test_attack_and_benign():
    alerts = security.detect(events())
    assert [a["rule"] for a in alerts] == [
        "repeated_login_failure",
        "success_after_failures",
    ]
    assert all(a["host"] == "lab-linux" for a in alerts)


def test_out_of_order():
    assert security.detect(events()[::-1]) == security.detect(events())


def test_window_expiry():
    rows = events()[:5]
    rows[-1]["timestamp"] = "2026-01-15T09:20:00Z"
    assert security.detect(rows) == []


def test_separate_hosts():
    rows = events()[:5]
    rows[-1]["host"] = "other"
    assert security.detect(rows) == []


def test_timezone_required():
    rows = events()[:1]
    rows[0]["timestamp"] = "2026-01-15T09:00:00"
    with pytest.raises(ValueError):
        security.detect(rows)


@pytest.mark.parametrize('bad', [None, [], {}, {'timestamp':12}])
def test_invalid_shapes(bad):
    with pytest.raises(ValueError):
        security.detect([bad])


@pytest.mark.parametrize('field,value',[('source_ip','not-an-ip'),('host',' '),('user',[]),('result','unknown'),('timestamp','yesterday')])
def test_invalid_fields(field,value):
    event=events()[0]
    event[field]=value
    with pytest.raises(ValueError):
        security.detect([event])


def test_duplicates_and_override():
    event=events()[0]
    assert security.detect([event]*5)==[]
    assert len(security.detect([event]*5,deduplicate=False))==1


def test_inclusive_boundary_and_timezone():
    rows=events()[:5]
    rows[-1]['timestamp']='2026-01-15T10:05:00+01:00'
    assert len(security.detect(rows))==1
    rows[-1]['timestamp']='2026-01-15T09:05:00.000001Z'
    assert security.detect(rows)==[]


def test_password_spray_isolation_and_suppression():
    rows=[dict(e,user=f'user{i}') for i,e in enumerate(events()[:5])]
    alerts=security.detect(rows)
    assert [a['rule'] for a in alerts]==['possible_password_spray']
    assert alerts[0]['distinct_users']==5
    rows[-1]['host']='another-host'
    assert security.detect(rows)==[]
    assert security.detect(events(),ignore_ips=['192.0.2.10'])==[]


def test_success_resets_and_no_repeat_alert():
    rows=events()[:5]
    rows.append(dict(rows[-1],timestamp='2026-01-15T09:04:30Z'))
    assert len(security.detect(rows))==1
    rows += [events()[5],dict(events()[5],timestamp='2026-01-15T09:05:01Z')]
    assert len(security.detect(rows))==2


@pytest.mark.parametrize('kwargs',[{'threshold':True},{'threshold':1},{'window':0},{'window':float('nan')},{'spray_threshold':1}])
def test_bad_configuration(kwargs):
    with pytest.raises(ValueError):
        security.detect([],**kwargs)


def test_jsonl_errors_and_cli(tmp_path,capsys):
    source=tmp_path/'events.jsonl'; output=tmp_path/'alerts.json'
    source.write_text(json.dumps(events()[0])+'\nnot json\nnull\n')
    with pytest.raises(ValueError,match='Line 2'):
        security.read_events(source)
    valid,rejects=security.read_events(source,True)
    assert len(valid)==1 and [r['line'] for r in rejects]==[2,3]
    assert security.main(['--input',str(source),'--output',str(output),'--skip-invalid'])==0
    assert json.loads(output.read_text())==[]
    with pytest.raises(SystemExit) as error:
        security.main(['--input',str(source),'--output',str(source)])
    assert error.value.code==2
    assert source.read_text().endswith('null\n')
