"""
correlator.py — Incident Correlation Engine (Feature 2)
 
Correlation strategy (priority order):
 
  STEP 1 — correlation_id grouping (PRIMARY)
    Same correlation_id = always same incident (explicit chain link).
    Window: up to 2 hours. If span > 2h, split into 60-min sub-windows.
 
  STEP 2 — secondary grouping
    - Same principal + same calendar day + within 60 min
    - Same namespace + within 10 min
    - Same source_ip + within 10 min
 
  KEY: principal match is SAME-DAY ONLY.
    dev-22 on June 3 and dev-22 on June 27 = TWO separate incidents.
 
  Incident IDs are DETERMINISTIC — same signals always produce same ID.
  This ensures narratives.json from feature4_main.py stays valid
  across multiple dashboard runs.
"""
 
from __future__ import annotations
 
import hashlib
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
 
 
MITRE_MAP = {
    "public_ip_on_ephemeral":        "T1190",
    "privileged_no_controller":      "T1610",
    "off_hours_high_priv":           "T1078",
    "novel_principal_high_priv":     "T1078",
    "burst_resource_creation":       "T1496",
    "untagged_high_priv_ephemeral":  "T1036",
    "k8s_public_exposure":           "T1190",
    "identity_off_hours_federated":  "T1078",
}
 
WINDOW_PRIMARY   = timedelta(minutes=60)
WINDOW_SECONDARY = timedelta(minutes=10)
 
 
@dataclass
class Incident:
    incident_id:      str
    signals:          list
    burst_events:     list
    principals:       list
    namespaces:       list
    sources:          list
    time_window:      tuple
    duration_minutes: float
    incident_score:   float
    severity:         str
    mitre_techniques: list
    incident_type:    str
    evidence:         list
    correlation_ids:  list
 
 
def _ts(sig) -> datetime:
    t = getattr(sig, "timestamp", None)
    if isinstance(t, datetime):
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(t).replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
    except Exception:
        return datetime(2024, 1, 1, tzinfo=timezone.utc)
 
 
def _severity(score: float) -> str:
    if score >= 3.5: return "CRITICAL"
    if score >= 2.0: return "HIGH"
    if score >= 0.8: return "MEDIUM"
    return "LOW"
 
 
def _incident_type(mitre: list) -> str:
    s = set(mitre)
    if "T1496" in s: return "resource_hijacking"
    if "T1190" in s and "T1078" in s: return "mixed"
    if "T1190" in s or "T1610" in s: return "public_exposure"
    if "T1078" in s: return "identity_abuse"
    return "mixed"
 
 
def _bursts_in_window(bursts, t_start, t_end):
    lo = t_start - timedelta(minutes=2)
    hi = t_end   + timedelta(minutes=2)
    result = []
    for b in bursts:
        bt = getattr(b, "timestamp", None)
        if bt is None:
            continue
        if not isinstance(bt, datetime):
            try:
                bt = datetime.fromisoformat(str(bt).replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
            except Exception:
                continue
        bt = bt if bt.tzinfo else bt.replace(tzinfo=timezone.utc)
        if lo <= bt <= hi:
            result.append(b)
    return result
 
 
def _make_incident_id(group_signals) -> str:
    """
    Deterministic incident ID based on the correlation IDs and entity IDs
    of the signals in the group. Same signals = same ID across runs.
    This ensures narratives.json stays valid without re-running feature4_main.py.
    """
    parts = sorted(
        getattr(s, "correlation_id", "") or getattr(s, "entity_id", "")
        for s in group_signals
    )
    hash_input = "".join(parts)
    return "INC-" + hashlib.md5(hash_input.encode()).hexdigest()[:8].upper()
 
 
def _build_incident(group_signals, bursts) -> Incident:
    timestamps = [_ts(s) for s in group_signals]
    t_start    = min(timestamps)
    t_end      = max(timestamps)
    duration   = (t_end - t_start).total_seconds() / 60
 
    principals = list(dict.fromkeys(
        s.entity_id for s in group_signals
        if getattr(s, "entity_type", "") in ("identity", "k8s") and s.entity_id
    ))
    namespaces = list(dict.fromkeys(
        s.namespace for s in group_signals if getattr(s, "namespace", "")
    ))
    sources = list(dict.fromkeys(
        s.source for s in group_signals if getattr(s, "source", "")
    ))
    corr_ids = list(dict.fromkeys(
        s.correlation_id for s in group_signals if getattr(s, "correlation_id", "")
    ))
    mitre_raw = [MITRE_MAP.get(getattr(s, "signal_type", ""), "") for s in group_signals]
    mitre     = list(dict.fromkeys(m for m in mitre_raw if m))
 
    scores    = [float(getattr(s, "score", 0)) for s in group_signals]
    max_score = max(scores) if scores else 0.0
    inc_score = round(max_score * math.log2(len(group_signals) + 1), 3)
 
    top      = sorted(group_signals, key=lambda s: float(getattr(s, "score", 0)), reverse=True)[:5]
    evidence = [getattr(s, "evidence", "") for s in top if getattr(s, "evidence", "")]
 
    return Incident(
        incident_id      = _make_incident_id(group_signals),
        signals          = group_signals,
        burst_events     = _bursts_in_window(bursts, t_start, t_end),
        principals       = principals,
        namespaces       = namespaces,
        sources          = sources,
        time_window      = (t_start, t_end),
        duration_minutes = round(duration, 1),
        incident_score   = inc_score,
        severity         = _severity(inc_score),
        mitre_techniques = mitre,
        incident_type    = _incident_type(mitre),
        evidence         = evidence,
        correlation_ids  = corr_ids,
    )
 
 
class _UF:
    def __init__(self, n):
        self.p = list(range(n))
        self.r = [0] * n
 
    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x
 
    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb: return
        if self.r[ra] < self.r[rb]: ra, rb = rb, ra
        self.p[rb] = ra
        if self.r[ra] == self.r[rb]: self.r[ra] += 1
 
 
def _link_by_time(signals, idx_list, uf, window):
    if len(idx_list) < 2:
        return
    pairs = sorted([(signals[i], i) for i in idx_list], key=lambda x: _ts(x[0]))
    for j in range(len(pairs)):
        for k in range(j + 1, len(pairs)):
            if _ts(pairs[k][0]) - _ts(pairs[j][0]) > window:
                break
            uf.union(pairs[j][1], pairs[k][1])
 
 
def correlate(signals, bursts, pipeline=None):
    if not signals:
        return []
 
    n  = len(signals)
    uf = _UF(n)
 
    corr_index:    dict = defaultdict(list)
    principal_day: dict = defaultdict(list)
    ns_idx:        dict = defaultdict(list)
    ip_idx:        dict = defaultdict(list)
 
    for i, sig in enumerate(signals):
        t   = _ts(sig)
        cid = getattr(sig, "correlation_id", "")
        eid = getattr(sig, "entity_id", "")
        ns  = getattr(sig, "namespace", "")
        ip  = getattr(sig, "source_ip", "")
 
        if cid: corr_index[cid].append(i)
        if eid: principal_day[(eid, t.date())].append(i)
        if ns:  ns_idx[ns].append(i)
        if ip and ip not in ("internal", ""): ip_idx[ip].append(i)
 
    # Step 1: correlation_id groups
    for cid, idx_list in corr_index.items():
        if len(idx_list) < 2:
            continue
        ts_sorted = sorted(idx_list, key=lambda i: _ts(signals[i]))
        ts_vals   = [_ts(signals[i]) for i in ts_sorted]
        span_hrs  = (ts_vals[-1] - ts_vals[0]).total_seconds() / 3600
 
        if span_hrs <= 2.0:
            for a, b in zip(ts_sorted, ts_sorted[1:]):
                uf.union(a, b)
        else:
            _link_by_time(signals, idx_list, uf, WINDOW_PRIMARY)
 
    # Step 2a: same principal, same day, within 60 min
    for (eid, day), idx_list in principal_day.items():
        _link_by_time(signals, idx_list, uf, WINDOW_PRIMARY)
 
    # Step 2b: same namespace within 10 min
    for ns, idx_list in ns_idx.items():
        _link_by_time(signals, idx_list, uf, WINDOW_SECONDARY)
 
    # Step 2c: same source_ip within 10 min
    for ip, idx_list in ip_idx.items():
        _link_by_time(signals, idx_list, uf, WINDOW_SECONDARY)
 
    # Build groups
    groups = defaultdict(list)
    for i in range(n):
        groups[uf.find(i)].append(i)
 
    incidents = []
    for root, indices in groups.items():
        group_signals = [signals[i] for i in indices]
        incidents.append(_build_incident(group_signals, bursts))
 
    incidents.sort(key=lambda x: x.incident_score, reverse=True)
    return incidents
 