# Detection and triage notes

All bundled logs are synthetic and use documentation-range IP addresses. Alert severity is a prioritization heuristic, not a probability of compromise. Password managers with stale credentials, shared NAT egress, scanners and users mistyping passwords can generate these patterns.

Check account ownership, expected source, MFA outcomes, endpoint/process activity and session history. Preserve original logs. Only recommend session revocation or credential resets when evidence and the organization's response policy justify them. No real containment is performed here.

Exact-event deduplication trades duplicate-ingest resistance for possible undercounting of identical legitimate events. Source event IDs would be safer. IP exclusions can hide malicious activity. `--skip-invalid` can omit crucial evidence; inspect rejected line counts/reasons. Raw logs and reports can contain usernames and internal addresses: sanitize before publishing. No secrets are needed.

Scope: normalized JSONL, batch processing, same-host/IP correlations. No native parser, streaming guarantees, cross-IP spray detection, incident case management or validated SIEM integration. Rule precision/recall has not been measured on representative real traffic.
