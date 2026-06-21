from __future__ import annotations
 
from dataclasses import dataclass
from datetime import datetime, timezone
import numpy as np
from collections import defaultdict
 
 
@dataclass
class BurstEvent:
    namespace:   str
    event_type:  str
    timestamp:   datetime
    count:       int
    zscore:      float
    iqr_flag:    bool
    severity:    str   # HIGH / MEDIUM
 
 
def _severity(zscore: float) -> str:
    return "HIGH" if zscore >= 5.0 else "MEDIUM"
 
 
def _bucket_key(ts: datetime) -> datetime:
    """Floor timestamp to 5-minute bucket."""
    minute = (ts.minute // 5) * 5
    return ts.replace(minute=minute, second=0, microsecond=0)
 
 
def detect_bursts(pipeline) -> list[BurstEvent]:
    """
    Detect burst events across the unified event stream.
    Returns list[BurstEvent] — only buckets that exceed Z-score or IQR threshold.
    """
    events = getattr(pipeline, "event_stream", [])
    if not events:
        return []
 
    # Group events by (namespace, event_type) → bucket → count
    bucket_counts: dict[tuple, dict[datetime, int]] = defaultdict(lambda: defaultdict(int))
 
    for ev in events:
        ts = getattr(ev, "timestamp", None)
        if ts is None:
            continue
        if not isinstance(ts, datetime):
            try:
                ts = datetime.fromisoformat(str(ts)).replace(tzinfo=timezone.utc)
            except Exception:
                continue
        ns  = getattr(ev, "namespace", "") or "unknown"
        et  = getattr(ev, "event_type", "") or "unknown"
        bkt = _bucket_key(ts)
        bucket_counts[(ns, et)][bkt] += 1
 
    bursts: list[BurstEvent] = []
 
    for (ns, et), buckets in bucket_counts.items():
        if len(buckets) < 3:
            # Need at least 3 buckets for a meaningful baseline
            continue
 
        counts      = np.array(list(buckets.values()), dtype=float)
        timestamps  = list(buckets.keys())
 
        mean  = counts.mean()
        std   = counts.std()
        q1    = np.percentile(counts, 25)
        q3    = np.percentile(counts, 75)
        iqr   = q3 - q1
 
        z_threshold   = mean + 3 * std if std > 0 else mean + 1
        iqr_threshold = q3 + 1.5 * iqr if iqr > 0 else q3 + 1
 
        for ts, cnt in zip(timestamps, counts):
            z_flag   = cnt > z_threshold
            iqr_flag = cnt > iqr_threshold
 
            if not (z_flag or iqr_flag):
                continue
 
            zscore = (cnt - mean) / std if std > 0 else 0.0
 
            bursts.append(BurstEvent(
                namespace  = ns,
                event_type = et,
                timestamp  = ts,
                count      = int(cnt),
                zscore     = round(float(zscore), 3),
                iqr_flag   = bool(iqr_flag),
                severity   = _severity(float(zscore)),
            ))
 
    bursts.sort(key=lambda b: b.timestamp)
    return bursts