# Authentication Log Analyzer

[Live browser demo](https://lacetears.github.io/it-career-portfolio/security.html)

A small defensive-security project that flags repeated failed logins and a successful login shortly afterward. It includes a synthetic event fixture, a written investigation, and tests for the correlation logic.

**Python · JSONL · Log correlation · Incident triage**

## Run
```sh
python cybersecurity/detect.py
```
Expected output:
```text
Analyzed 8 synthetic/local events; generated 2 alerts.
```
Open [`alerts.json`](cybersecurity/reports/alerts.json) and the [incident report](cybersecurity/reports/incident-report.md).

## What triggers an alert?
Five failures within a rolling 300-second window for the same host, source IP, and username raise a repeated-failure alert. A success while that threshold is still met raises a higher-priority alert. Success clears that group's failure history. Input is sorted by time before evaluation.

In the fixture, `demo` fails five times on `lab-linux`, then succeeds. A second user fails once and succeeds without triggering an alert. The addresses are documentation addresses and every event is synthetic.

## Investigation, not proof
The alert is a starting point for triage. A user forgetting a password could produce the same sequence. The report identifies missing evidence, follow-up questions, and conditional response steps. No compromise or real containment action is claimed.

## Input contract
One JSON object per line with `timestamp`, `host`, `source_ip`, `user`, and `result`. Timestamps must include a timezone. Result is `failure` or `success`. This version accepts normalized JSONL, not native Windows events or raw syslog. Malformed input fails explicitly.

```sh
python cybersecurity/detect.py --input cybersecurity/data/auth_events.jsonl --output cybersecurity/reports/alerts.json
```

## Test
```sh
python -m pip install -r requirements.txt
python -m pytest -q
```
Tests cover expected alerts, shuffled input, expired windows, host isolation, and timezone validation.

## Boundaries and next steps
This detector does not identify distributed password spraying or correlate multiple users. Duplicate source events can inflate counts. Thresholds need tuning against real baseline activity. The current implementation loads input into memory.

A [Wazuh lab guide](cybersecurity/README.md) and sample SSH rule are included as an extension. A live SIEM with Windows/Linux endpoints has not been deployed or verified. Wazuh's rule behavior is not assumed to be identical to this Python detector.

[Development notes](docs/development.md)
