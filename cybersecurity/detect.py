"""Batch correlation for normalized authentication JSONL. Alerts need human triage."""

import argparse
import ipaddress
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ('timestamp', 'host', 'source_ip', 'user', 'result')


def normalize(event):
    """Validate identity fields and normalize timestamps/IPs before correlation."""
    if not isinstance(event, dict):
        raise ValueError('Event must be a JSON object')
    for field in FIELDS:
        value = event.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 512:
            raise ValueError(f'{field} must be a nonempty string of at most 512 characters')
    row = {field: event[field].strip() for field in FIELDS}
    if row['result'] not in ('failure', 'success'):
        raise ValueError('Unsupported result')
    try:
        timestamp = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
        if timestamp.utcoffset() is None:
            raise ValueError('Timezone required')
        row['timestamp'] = timestamp.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
        row['source_ip'] = str(ipaddress.ip_address(row['source_ip']))
    except (ValueError, OverflowError) as error:
        raise ValueError(f'Invalid timestamp or source_ip: {error}') from error
    return row


def read_events(path, skip_invalid=False):
    """Strict by default. Optional quarantine reports line/reason, never raw log data."""
    events, rejected = [], []
    with Path(path).open(encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                events.append(normalize(json.loads(line)))
            except (ValueError, TypeError) as error:
                if not skip_invalid:
                    raise ValueError(f'Line {number}: {error}') from error
                rejected.append({'line': number, 'reason': str(error)})
    return events, rejected


def detect(events, threshold=5, window=300, spray_threshold=5, deduplicate=True, ignore_ips=()):
    """Inclusive rolling windows; equal timestamps retain input order.

    Exact normalized duplicates are suppressed by default. Disable this when the
    source can record distinct identical events at its timestamp precision.
    """
    for name, value, minimum in (('threshold', threshold, 2), ('window', window, 1), ('spray_threshold', spray_threshold, 2)):
        if type(value) is not int or value < minimum:
            raise ValueError(f'{name} must be an integer >= {minimum}')
    ignored = {str(ipaddress.ip_address(ip)) for ip in ignore_ips}
    rows, seen = [], set()
    for event in events:
        row = normalize(event)
        signature = tuple(row[field] for field in FIELDS)
        if row['source_ip'] in ignored or (deduplicate and signature in seen):
            continue
        seen.add(signature)
        rows.append((datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')), row))
    failures, spray = defaultdict(deque), defaultdict(deque)
    active, spray_active = set(), set()
    alerts = []
    for timestamp, event in sorted(rows, key=lambda item: item[0]):
        key = (event['host'], event['source_ip'], event['user'])
        queue = failures[key]
        while queue and (timestamp - queue[0]).total_seconds() > window:
            queue.popleft()
        if len(queue) < threshold:
            active.discard(key)
        kind = None
        if event['result'] == 'failure':
            queue.append(timestamp)
            if len(queue) >= threshold and key not in active:
                kind = 'repeated_login_failure'
                active.add(key)
        elif len(queue) >= threshold:
            kind = 'success_after_failures'
        if kind:
            alerts.append(dict(rule=kind, severity='high' if event['result']=='success' else 'medium', **{f:event[f] for f in FIELDS if f!='result'}, failure_count=len(queue), window_seconds=window))
        if event['result'] == 'success':
            queue.clear()
            active.discard(key)
        # Spray correlation is independent: success for one account must not erase
        # failures against other accounts on the same destination host.
        spray_key = key[:2]
        attempts = spray[spray_key]
        while attempts and (timestamp - attempts[0][0]).total_seconds() > window:
            attempts.popleft()
        users = {user for _, user in attempts}
        if len(users) < spray_threshold:
            spray_active.discard(spray_key)
        if event['result'] == 'failure':
            attempts.append((timestamp, event['user']))
            users.add(event['user'])
            if len(users) >= spray_threshold and spray_key not in spray_active:
                alerts.append(dict(rule='possible_password_spray',severity='medium',timestamp=event['timestamp'],host=event['host'],source_ip=event['source_ip'],users=sorted(users),distinct_users=len(users),failure_count=len(attempts),window_seconds=window))
                spray_active.add(spray_key)
    return alerts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    base = Path(__file__).parent
    parser.add_argument('--input', type=Path, default=base/'data/auth_events.jsonl')
    parser.add_argument('--output', type=Path, default=base/'reports/alerts.json')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window', type=int, default=300)
    parser.add_argument('--spray-threshold', type=int, default=5)
    parser.add_argument('--keep-duplicates', action='store_true')
    parser.add_argument('--ignore-ip', action='append', default=[])
    parser.add_argument('--skip-invalid', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError('Input and output must be different files')
        events, rejected = read_events(args.input, args.skip_invalid)
        alerts = detect(events, args.threshold, args.window, args.spray_threshold, not args.keep_duplicates, args.ignore_ip)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(alerts, indent=2)+'\n', encoding='utf-8')
    except (OSError, ValueError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(json.dumps(dict(valid_events=len(events),rejected_lines=rejected,alerts=len(alerts),deduplicate=not args.keep_duplicates,ignored_ips=args.ignore_ip)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
