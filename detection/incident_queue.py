"""
incident_queue.py — Sort and annotate the correlated incident list.

build_queue(incidents) → IncidentQueue

IncidentQueue exposes:
  • incidents            — sorted by incident_score descending
  • total_raw_signals    — sum of all signals across all incidents
  • total_incidents      — number of Incident objects
  • alert_reduction_pct  — (raw_signals - incidents) / raw_signals × 100
  • stats                — breakdown by severity and incident_type
"""
from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import List

from detection.correlator import Incident
from detection.signal_scorer import RiskSignal


@dataclass
class IncidentQueue:
    incidents:           List[Incident]
    total_raw_signals:   int
    total_incidents:     int
    alert_reduction_pct: float
    stats:               dict


def top_evidence(incident: Incident, n: int = 3) -> List[str]:
    """Return evidence strings from the top-n signals by score."""
    top = sorted(incident.signals, key=lambda s: s.score, reverse=True)[:n]
    return [s.evidence for s in top]


def build_queue(incidents: List[Incident]) -> IncidentQueue:
    """
    Sort incidents by incident_score (descending) and compute summary metrics.
    alert_reduction_pct measures how much alert noise the correlation engine
    absorbed: each incident replaces N raw signals with a single case.
    """
    sorted_incidents = sorted(
        incidents, key=lambda inc: inc.incident_score, reverse=True
    )

    # total_raw_signals = total individual RiskSignals across all incidents
    # (Union-Find guarantees every signal is in exactly one incident)
    total_signals = sum(len(inc.signals) for inc in incidents)
    total_inc     = len(incidents)

    reduction = 0.0
    if total_signals > 0:
        reduction = (total_signals - total_inc) / total_signals * 100.0

    # Aggregate stats
    by_severity: dict[str, int] = defaultdict(int)
    by_type:     dict[str, int] = defaultdict(int)
    for inc in incidents:
        by_severity[inc.severity]      += 1
        by_type[inc.incident_type]     += 1

    stats = {
        "by_severity": dict(by_severity),
        "by_type":     dict(by_type),
    }

    return IncidentQueue(
        incidents           = sorted_incidents,
        total_raw_signals   = total_signals,
        total_incidents     = total_inc,
        alert_reduction_pct = round(reduction, 1),
        stats               = stats,
    )
