from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class IncidentQueue:
    incidents: list
    total_raw_signals: int
    total_incidents: int
    alert_reduction_pct: float
    stats: dict[str, Any]


def build_queue(incidents: list, raw_signal_count: int = 0) -> IncidentQueue:
    """
    Build sorted incident queue with alert reduction stats.

    Parameters
    ----------
    incidents : list[Incident]
        Incidents returned by correlator.correlate()

    raw_signal_count : int
        Total number of raw signals before correlation
    """

    # Sort incidents by score (highest first)
    sorted_incidents = sorted(
        incidents,
        key=lambda i: i.incident_score,
        reverse=True
    )

    total_incidents = len(sorted_incidents)

    # Calculate alert reduction
    if raw_signal_count > 0 and raw_signal_count > total_incidents:
        reduction = round(
            (raw_signal_count - total_incidents)
            / raw_signal_count
            * 100,
            1,
        )
    else:
        total_signal_events = sum(
            len(getattr(i, "signals", []))
            for i in sorted_incidents
        )

        if total_signal_events > total_incidents:
            reduction = round(
                (total_signal_events - total_incidents)
                / total_signal_events
                * 100,
                1,
            )
        else:
            reduction = 0.0

    # Build statistics
    by_severity: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    by_type: dict[str, int] = {}

    for inc in sorted_incidents:
        sev = getattr(inc, "severity", "LOW")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        incident_type = getattr(inc, "incident_type", "mixed")
        by_type[incident_type] = by_type.get(incident_type, 0) + 1

    stats = {
        "by_severity": by_severity,
        "by_incident_type": by_type,
    }

    return IncidentQueue(
        incidents=sorted_incidents,
        total_raw_signals=raw_signal_count,
        total_incidents=total_incidents,
        alert_reduction_pct=reduction,
        stats=stats,
    )


def top_evidence(incident, n: int = 5) -> list[str]:
    """
    Return top-n evidence strings from an incident.
    """
    return getattr(incident, "evidence", [])[:n]