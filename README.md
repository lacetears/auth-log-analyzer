# Authentication Log Analyzer

A Python command-line tool for triaging normalized authentication logs. It detects repeated failures, success after failures, and possible password spraying across accounts. The included examples are synthetic; an alert is evidence to investigate, not proof of compromise.

## Run

Python 3.12 or 3.13; detection uses only the standard library.

```sh
python cybersecurity/detect.py
python cybersecurity/detect.py --input cybersecurity/data/spray_events.jsonl --output cybersecurity/reports/spray-alerts.json --window 300 --spray-threshold 5
python -m pip install -r requirements.txt
python -m pytest -q
```

The original eight-event fixture produces two alerts. The spray fixture produces one possible-password-spray alert. CI runs both scenarios and the test suite.

## Input and output

One JSON object per nonblank line:

```json
{"timestamp":"2026-01-15T09:00:00Z","host":"lab-linux","source_ip":"192.0.2.10","user":"demo","result":"failure"}
```

All five fields must be nonempty strings, at most 512 characters. Results are `failure` or `success`; timestamps require an offset; IP addresses must parse as IPv4/IPv6. Timestamps and IPs are normalized. Extra fields are ignored. This is not a raw syslog or Windows Event Log parser.

Alerts are written as a JSON array with rule, severity, time, host, source and supporting counts. CLI stdout reports valid events, rejected line numbers/reasons, alert count and suppression settings. Valid-event count is before deduplication and IP exclusion. Malformed input fails with an actionable line number and exit code 2. `--skip-invalid` explicitly opts into skipping invalid records; inspect the reported exclusions. The input file cannot also be the output file.

## Correlation architecture

Validation → UTC normalization → stable timestamp sort → keyed rolling queues → JSON alerts.

- Five failures in an inclusive 300-second window for the same host/IP/user produce a repeated-failure alert. Another is suppressed while the group remains above threshold.
- A success while that group meets the threshold produces a higher-priority alert, then resets the group.
- Five distinct failing usernames on the same host/IP in the window produce a possible-password-spray alert. Success for one user does not erase other users' failures.
- Equal-time events retain input order. An event exactly 300 seconds old is included; older events expire.

Thresholds are configurable with `--threshold`, `--window` and `--spray-threshold`. Exact normalized duplicates are removed by default. This can collapse legitimate identical attempts from low-resolution sources; `--keep-duplicates` preserves them. Repeated `--ignore-ip` options explicitly suppress known sources and are recorded in the CLI summary. An exclusion can hide attacks; document why it exists and when to review it.

## Verification and engineering decisions

Tests exercise malformed JSON/schema/IPs, timezone normalization, inclusive boundaries, shuffled input, host isolation, duplicates, reset/suppression behavior, spray correlation, invalid configuration and CLI errors. The batch sort tolerates out-of-order input but requires memory proportional to input size; this is not a streaming SIEM. No throughput measurement is claimed.

[Incident walkthrough](cybersecurity/reports/incident-report.md) explains the original synthetic sequence. [Triage and limitations](SECURITY.md) describes false positives and missing evidence.

[Earlier browser demo](https://lacetears.github.io/it-career-portfolio/security.html) and its [existing screenshot](docs/screenshot.jpg) are separate JavaScript demonstrations and do not implement every Python feature. Wazuh files are unverified extension examples, not evidence of a deployed SIEM.

## Next steps

Add source-specific Windows/Linux adapters with provenance and event IDs, labeled benign/attack evaluation data, and bounded streaming state. Distributed low-and-slow attacks across IPs remain outside this detector's rules.
