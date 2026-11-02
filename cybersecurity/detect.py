"""Detect repeated failures and subsequent successes in normalized JSONL events."""
import argparse,json
from collections import defaultdict,deque
from datetime import datetime
from pathlib import Path
def detect(events, threshold=5, window=300):
    if threshold<2 or window<1: raise ValueError('Invalid threshold or window')
    failures=defaultdict(deque); active=set(); alerts=[]
    rows=[]
    for e in events:
        if e['result'] not in ('failure','success'): raise ValueError('Unsupported result')
        t=datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'))
        if t.tzinfo is None: raise ValueError('Timezone required')
        rows.append((t,e))
    for t,e in sorted(rows,key=lambda row:row[0]):
        key=(e['host'],e['source_ip'],e['user']); queue=failures[key]
        while queue and (t-queue[0]).total_seconds()>window: queue.popleft()
        if len(queue)<threshold: active.discard(key)
        kind=None
        if e['result']=='failure':
            queue.append(t)
            if len(queue)>=threshold and key not in active:
                kind='repeated_login_failure'; active.add(key)
        elif len(queue)>=threshold:
            kind='success_after_failures'
        if kind:
            alerts.append(dict(rule=kind,severity='high' if e['result']=='success' else 'medium',timestamp=e['timestamp'],host=e['host'],source_ip=e['source_ip'],user=e['user'],failure_count=len(queue),window_seconds=window))
        if e['result']=='success': queue.clear(); active.discard(key)
    return alerts
if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--input',type=Path,default=Path(__file__).parent/'data/auth_events.jsonl'); parser.add_argument('--output',type=Path,default=Path(__file__).parent/'reports/alerts.json'); args=parser.parse_args()
    events=[json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    alerts=detect(events); args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(alerts,indent=2)+'\n')
    print(f'Analyzed {len(events)} synthetic/local events; generated {len(alerts)} alerts.')
