"""
correlator.py — Group RiskSignals + BurstEvents into correlated Incidents.

Correlation axes (any match → merge via Union-Find):
  1. Same correlation_id (explicit cross-source link, no time constraint)
  2. Same principal_id within a 5-minute sliding window
  3. Same namespace   within a 5-minute sliding window
  4. Same source_ip   within a 5-minute sliding window

Incident scoring:  max_signal_score × log2(signal_count + 1)
Severity cutoffs:  critical ≥ 1.2 | high ≥ 0.8 | medium ≥ 0.5 | low < 0.5

correlate(signals, bursts, pipeline) → list[Incident]
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Tuple

from detection.signal_scorer import RiskSignal
from detection.burst_detector import BurstEvent

# ── MITRE ATT&CK mapping per signal type ──────────────────────────────────────
MITRE_MAP: dict[str, str] = {
    "public_ip_on_ephemeral":        "T1190",   # Exploit Public-Facing Application
    "privileged_no_controller":      "T1610",   # Deploy Container
    "off_hours_assume_role":         "T1078",   # Valid Accounts
    "burst_threshold_exceeded":      "T1496",   # Resource Hijacking
    "novel_principal_high_priv":     "T1078",   # Valid Accounts
    "untagged_ephemeral":            "T1036",   # Masquerading
    "cross_namespace_access":        "T1078",   # Valid Accounts
    "short_lived_high_priv_session": "T1078",   # Valid Accounts
}

# ── Incident type classification ───────────────────────────────────────────────
_TYPE_MAP: dict[str, str] = {
    "public_ip_on_ephemeral":        "public_exposure",
    "untagged_ephemeral":            "public_exposure",
    "privileged_no_controller":      "resource_hijacking",
    "burst_threshold_exceeded":      "resource_hijacking",
    "off_hours_assume_role":         "identity_abuse",
    "novel_principal_high_priv":     "identity_abuse",
    "short_lived_high_priv_session": "identity_abuse",
    "cross_namespace_access":        "identity_abuse",
}

_CORRELATION_WINDOW_SECS = 300   # 5 minutes
_BURST_ASSOC_SLACK = timedelta(minutes=5)


@dataclass
class Incident:
    """A correlated group of risk signals representing one security incident."""
    incident_id:      str
    signals:          List[RiskSignal]
    burst_events:     List[BurstEvent]
    principals:       List[str]
    namespaces:       List[str]
    time_window:      Tuple[datetime, datetime]
    incident_score:   float
    severity:         str
    mitre_techniques: List[str]
    incident_type:    str


# ── Union-Find ─────────────────────────────────────────────────────────────────

class _UF:
    __slots__ = ("p",)

    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]   # path compression
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        pa, pb = self.find(a), self.find(b)
        if pa != pb:
            self.p[pa] = pb


# ── Helpers ────────────────────────────────────────────────────────────────────

def _incident_id(sigs: List[RiskSignal]) -> str:
    key = "".join(sorted(s.signal_id for s in sigs))
    return "INC-" + hashlib.md5(key.encode()).hexdigest()[:8].upper()


def _severity(score: float) -> str:
    if score >= 1.2:
        return "critical"
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def _incident_type(sigs: List[RiskSignal]) -> str:
    types = {_TYPE_MAP.get(s.signal_type) for s in sigs if _TYPE_MAP.get(s.signal_type)}
    if len(types) > 1:
        return "mixed"
    return types.pop() if types else "mixed"


def _mitre(sigs: List[RiskSignal]) -> List[str]:
    techs = sorted({MITRE_MAP[s.signal_type] for s in sigs if s.signal_type in MITRE_MAP})
    return techs if techs else ["T1078"]   # default fallback


def _sliding_window_union(
    uf: _UF,
    signals: List[RiskSignal],
    sorted_idx: List[int],
    attr: str,
) -> None:
    """
    For signals sharing the same `attr` value, union pairs whose timestamps
    differ by at most _CORRELATION_WINDOW_SECS.  sorted_idx is pre-sorted by
    timestamp so we can use a two-pointer sweep (O(n) per attribute bucket).
    """
    buckets: dict[str, List[int]] = defaultdict(list)
    for i in sorted_idx:
        val = getattr(signals[i], attr, "")
        if val:
            buckets[val].append(i)

    for val, idxs in buckets.items():
        # idxs are already in timestamp order (inherited from sorted_idx)
        left = 0
        for right in range(1, len(idxs)):
            ir = idxs[right]
            # advance left pointer until within the window
            while left < right:
                dt = (
                    signals[ir].timestamp - signals[idxs[left]].timestamp
                ).total_seconds()
                if dt <= _CORRELATION_WINDOW_SECS:
                    break
                left += 1
            # every index from left to right-1 is within the window of right
            for k in range(left, right):
                uf.union(idxs[k], ir)


# ── Public API ─────────────────────────────────────────────────────────────────

def correlate(
    signals: List[RiskSignal],
    bursts:  List[BurstEvent],
    pipeline,
) -> List["Incident"]:
    """
    Group RiskSignals into Incidents using four correlation axes.
    Burst events are associated to incidents whose namespace+time_window overlap.

    Returns a list of Incident objects (unsorted).
    """
    if not signals:
        return []

    n  = len(signals)
    uf = _UF(n)

    # ── Axis 1: same entity_id (no time constraint — all signals per entity) ─────
    entity_buckets: dict[str, List[int]] = defaultdict(list)
    for i, s in enumerate(signals):
        if s.entity_id:
            entity_buckets[s.entity_id].append(i)
    for idxs in entity_buckets.values():
        for k in range(1, len(idxs)):
            uf.union(idxs[0], idxs[k])

    # ── Axis 2: same correlation_id (no time constraint) ──────────────────────
    corr_buckets: dict[str, List[int]] = defaultdict(list)
    for i, s in enumerate(signals):
        if s.correlation_id:
            corr_buckets[s.correlation_id].append(i)
    for idxs in corr_buckets.values():
        for k in range(1, len(idxs)):
            uf.union(idxs[0], idxs[k])

    # Sort indices once by timestamp for the sliding-window axes
    sorted_idx = sorted(range(n), key=lambda i: signals[i].timestamp)

    # ── Axes 3-5: within 5-minute window ──────────────────────────────────────
    _sliding_window_union(uf, signals, sorted_idx, "principal_id")
    _sliding_window_union(uf, signals, sorted_idx, "namespace")
    _sliding_window_union(uf, signals, sorted_idx, "source_ip")

    # ── Build incident groups ──────────────────────────────────────────────────
    groups: dict[int, List[int]] = defaultdict(list)
    for i in range(n):
        groups[uf.find(i)].append(i)

    # Pre-index burst events by namespace for fast association
    bursts_by_ns: dict[str, List[BurstEvent]] = defaultdict(list)
    for b in bursts:
        bursts_by_ns[b.namespace].append(b)

    incidents: List[Incident] = []
    for root, idxs in groups.items():
        sigs       = [signals[i] for i in idxs]
        timestamps = [s.timestamp for s in sigs]
        t_start    = min(timestamps)
        t_end      = max(timestamps)

        principals = sorted({s.principal_id for s in sigs if s.principal_id})
        namespaces = sorted({s.namespace    for s in sigs if s.namespace})

        max_score  = max(s.score for s in sigs)
        inc_score  = max_score * math.log2(len(sigs) + 1)
        inc_score  = round(inc_score, 4)

        # Associate burst events that overlap this incident's namespaces + window
        inc_bursts: List[BurstEvent] = []
        for ns in namespaces:
            for b in bursts_by_ns.get(ns, []):
                if (t_start - _BURST_ASSOC_SLACK) <= b.timestamp <= (t_end + _BURST_ASSOC_SLACK):
                    if b not in inc_bursts:
                        inc_bursts.append(b)

        incidents.append(Incident(
            incident_id      = _incident_id(sigs),
            signals          = sigs,
            burst_events     = inc_bursts,
            principals       = principals,
            namespaces       = namespaces,
            time_window      = (t_start, t_end),
            incident_score   = inc_score,
            severity         = _severity(inc_score),
            mitre_techniques = _mitre(sigs),
            incident_type    = _incident_type(sigs),
        ))

    return incidents
