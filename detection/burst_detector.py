"""
burst_detector.py — Rolling Z-score and IQR burst detection.

Groups events by (namespace, event_type), bins them into 5-minute windows,
and flags windows where count > rolling mean + 3σ (Z-score) or > Q3 + 1.5*IQR.

detect_bursts(pipeline) → list[BurstEvent]
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List

import numpy as np

_WINDOW = timedelta(minutes=5)
_BASELINE_WINDOWS = 12   # look back 12 × 5 min = 60 min


@dataclass
class BurstEvent:
    """A single 5-minute window that exceeded burst thresholds."""
    namespace:   str
    event_type:  str
    timestamp:   datetime       # start of the flagged window
    count:       int            # events in this window
    zscore:      float          # (count - baseline_mean) / baseline_std
    iqr_flag:    bool           # count > Q3 + 1.5 * IQR  (global IQR)
    severity:    str            # critical / high / medium / low


def _severity(zscore: float) -> str:
    if zscore > 5:
        return "critical"
    if zscore > 3:
        return "high"
    if zscore > 2:
        return "medium"
    return "low"


def detect_bursts(pipeline) -> List[BurstEvent]:
    """
    Detect burst windows per (namespace, event_type) using:
      • Rolling Z-score  — flag when count > rolling_mean + 3 × rolling_std
      • IQR method       — flag when count > Q3 + 1.5 × IQR  (over all windows)

    Returns a list of BurstEvent objects for all flagged windows.
    """
    bursts: List[BurstEvent] = []

    # Group event timestamps by (namespace, event_type)
    groups: dict[tuple[str, str], List[datetime]] = defaultdict(list)
    for event in pipeline.event_stream:
        ns = event.namespace or "default"
        groups[(ns, event.event_type)].append(event.timestamp)

    for (namespace, event_type), raw_timestamps in groups.items():
        if len(raw_timestamps) < 3:
            continue

        timestamps = sorted(raw_timestamps)
        t_min = timestamps[0]
        t_max = timestamps[-1]

        # Build contiguous 5-minute windows from t_min to t_max
        window_starts: List[datetime] = []
        window_counts: List[int] = []
        t = t_min
        while t <= t_max + _WINDOW:
            t_end = t + _WINDOW
            cnt = sum(1 for ts in timestamps if t <= ts < t_end)
            window_starts.append(t)
            window_counts.append(cnt)
            t += _WINDOW

        if len(window_counts) < 3:
            continue

        counts = np.array(window_counts, dtype=float)

        # Global IQR thresholds (over all windows for this key)
        q1  = float(np.percentile(counts, 25))
        q3  = float(np.percentile(counts, 75))
        iqr = q3 - q1
        iqr_upper = (q3 + 1.5 * iqr) if iqr > 0 else q3 * 1.5

        for i, (t_win, count) in enumerate(zip(window_starts, window_counts)):
            if count == 0:
                continue

            # Rolling baseline: the previous _BASELINE_WINDOWS windows
            start_idx = max(0, i - _BASELINE_WINDOWS)
            baseline  = counts[start_idx:i]

            if len(baseline) < 2:
                continue

            mean = float(np.mean(baseline))
            std  = float(np.std(baseline, ddof=1))

            if std < 0.5:
                # Too stable to compute a meaningful Z-score;
                # use a simple ratio instead to avoid inflation.
                zscore = float(count / mean - 1.0) if mean > 0 else 0.0
            else:
                zscore = float((count - mean) / std)

            iqr_flag = bool(count > iqr_upper)

            if zscore > 3 or iqr_flag:
                bursts.append(BurstEvent(
                    namespace=namespace,
                    event_type=event_type,
                    timestamp=t_win,
                    count=count,
                    zscore=round(zscore, 2),
                    iqr_flag=iqr_flag,
                    severity=_severity(zscore),
                ))

    return bursts
