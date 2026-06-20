"""
feature2_main.py — Entry point for Feature 2: Detection & Correlation Engine.

Runs Feature 1 (ingestion + enrichment + classification) then Feature 2
(signal scoring, burst detection, incident correlation, queue building),
prints a formatted incident queue, and saves results to outputs/incidents.json.

Usage:
    python feature2_main.py --data-dir data/
"""
from __future__ import annotations

import sys
import json
import argparse
import os
from datetime import datetime

sys.path.insert(0, ".")

# ── Feature 1 imports ──────────────────────────────────────────────────────────
from pipeline.ingestion import IngestionPipeline
from pipeline.enrichment import enrich
from classifier.ephemeral_classifier import EphemeralClassifier, ClassifierConfig

# ── Feature 2 imports ──────────────────────────────────────────────────────────
from detection.signal_scorer import score_all
from detection.burst_detector import detect_bursts
from detection.correlator import correlate, Incident
from detection.incident_queue import build_queue, top_evidence, IncidentQueue


# ── Formatting helpers ─────────────────────────────────────────────────────────

def _window_str(t0: datetime | None, t1: datetime | None) -> str:
    """Show HH:MM-HH:MM for same-day windows; include date for multi-day spans."""
    if t0 is None or t1 is None:
        return "??-??"
    if t0.date() == t1.date():
        return f"{t0.strftime('%H:%M')}-{t1.strftime('%H:%M')}"
    return f"{t0.strftime('%m/%d %H:%M')} to {t1.strftime('%m/%d %H:%M')}"


def _norm_score(score: float, severity: str) -> int:
    """Map raw incident_score to a 0-100 int within the severity band."""
    bands = {
        "critical": (1.2, 6.0, 85, 99),
        "high":     (0.8, 1.2, 70, 84),
        "medium":   (0.5, 0.8, 50, 69),
        "low":      (0.0, 0.5, 25, 49),
    }
    lo_s, hi_s, lo_n, hi_n = bands.get(severity, (0.0, 6.0, 0, 99))
    span = hi_s - lo_s
    frac = min(max((score - lo_s) / span if span > 0 else 1.0, 0.0), 1.0)
    return int(lo_n + frac * (hi_n - lo_n))


def _incident_to_dict(inc: Incident) -> dict:
    return {
        "incident_id":      inc.incident_id,
        "severity":         inc.severity,
        "incident_type":    inc.incident_type,
        "incident_score":   inc.incident_score,
        "mitre_techniques": inc.mitre_techniques,
        "principals":       inc.principals,
        "namespaces":       inc.namespaces,
        "time_window":      [
            inc.time_window[0].isoformat(),
            inc.time_window[1].isoformat(),
        ],
        "signal_count":     len(inc.signals),
        "burst_event_count": len(inc.burst_events),
        "evidence":         top_evidence(inc, n=3),
        "signals": [
            {
                "signal_id":   s.signal_id,
                "signal_type": s.signal_type,
                "score":       s.score,
                "entity_id":   s.entity_id,
                "evidence":    s.evidence,
                "timestamp":   s.timestamp.isoformat(),
                "principal_id":   s.principal_id,
                "namespace":      s.namespace,
                "source_ip":      s.source_ip,
                "correlation_id": s.correlation_id,
            }
            for s in sorted(inc.signals, key=lambda s: s.score, reverse=True)
        ],
        "burst_events": [
            {
                "namespace":  b.namespace,
                "event_type": b.event_type,
                "timestamp":  b.timestamp.isoformat(),
                "count":      b.count,
                "zscore":     b.zscore,
                "iqr_flag":   b.iqr_flag,
                "severity":   b.severity,
            }
            for b in inc.burst_events
        ],
    }


def _print_incident(rank: int, inc: Incident) -> None:
    win = _window_str(inc.time_window[0], inc.time_window[1])
    sev = inc.severity.upper()
    ns  = _norm_score(inc.incident_score, inc.severity)
    print(f"\n  #{rank}  {inc.incident_id}  [{ns} {sev}]  {inc.incident_type}")
    print(f"  Raw Score: {inc.incident_score:.3f}  |  Signals: {len(inc.signals)}  |  Window: {win}")
    if inc.principals:
        display_principals = inc.principals[:3]
        suffix = f" +{len(inc.principals)-3} more" if len(inc.principals) > 3 else ""
        print(f"  Principals: {display_principals}{suffix}")
    if inc.namespaces:
        print(f"  Namespaces: {inc.namespaces[:4]}")
    print(f"  MITRE: {', '.join(inc.mitre_techniques)}")
    if inc.burst_events:
        print(f"  Burst events: {len(inc.burst_events)}")
    print("  Evidence:")
    for snippet in top_evidence(inc, n=3):
        print(f"    * {snippet}")


def _validate(queue: IncidentQueue) -> dict[str, bool]:
    ok_reduction = queue.alert_reduction_pct >= 40.0
    ok_incidents = queue.total_incidents >= 20
    ok_mitre     = all(len(inc.mitre_techniques) > 0 for inc in queue.incidents)
    ok_evidence  = all(len(top_evidence(inc, n=1)) > 0 for inc in queue.incidents)
    return {
        "alert_reduction_ge_40": ok_reduction,
        "incidents_ge_20":       ok_incidents,
        "all_mitre_mapped":      ok_mitre,
        "all_have_evidence":     ok_evidence,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Feature 2 — Detection & Correlation Engine")
    parser.add_argument("--data-dir", default="data/", help="Path to data directory")
    args = parser.parse_args()

    # ── Header ─────────────────────────────────────────────────────────────────
    print()
    print("=" * 50)
    print("  FEATURE 2 - DETECTION & CORRELATION ENGINE")
    print("=" * 50)
    print()

    # ── Feature 1: ingest, enrich, classify ────────────────────────────────────
    pipeline = IngestionPipeline(data_dir=args.data_dir)
    pipeline.ingest()
    enrich(pipeline)
    clf     = EphemeralClassifier(ClassifierConfig())
    results = clf.classify_all(pipeline)

    # ── Step 1 ─────────────────────────────────────────────────────────────────
    print("[1/4] Scoring risk signals...     ", end="", flush=True)
    signals = score_all(pipeline, results)
    print(f"[OK] {len(signals)} signals detected")

    # ── Step 2 ─────────────────────────────────────────────────────────────────
    print("[2/4] Detecting bursts...         ", end="", flush=True)
    bursts = detect_bursts(pipeline)
    print(f"[OK] {len(bursts)} burst events")

    # ── Step 3 ─────────────────────────────────────────────────────────────────
    print("[3/4] Correlating incidents...    ", end="", flush=True)
    incidents = correlate(signals, bursts, pipeline)
    print(f"[OK] {len(incidents)} incidents")

    # ── Step 4 ─────────────────────────────────────────────────────────────────
    print("[4/4] Building incident queue...  ", end="", flush=True)
    queue = build_queue(incidents)
    print(f"[OK] Alert reduction: {queue.alert_reduction_pct:.1f}%")
    print()

    # ── Incident queue (top 10) ────────────────────────────────────────────────
    print("-" * 50)
    print("  INCIDENT QUEUE (top 10)")
    print("-" * 50)

    for rank, inc in enumerate(queue.incidents[:10], 1):
        _print_incident(rank, inc)

    # ── Summary ────────────────────────────────────────────────────────────────
    print()
    print("-" * 50)
    print("  SUMMARY")
    print("-" * 50)
    by_sev = queue.stats.get("by_severity", {})
    by_typ = queue.stats.get("by_type", {})
    print(f"  Total raw signals   : {queue.total_raw_signals}")
    print(f"  Incidents created   : {queue.total_incidents}")
    print(f"  Alert reduction     : {queue.alert_reduction_pct:.1f}%  (target >=40%)")
    print(f"  Critical incidents  : {by_sev.get('critical', 0)}")
    print(f"  High incidents      : {by_sev.get('high', 0)}")
    print(f"  Medium incidents    : {by_sev.get('medium', 0)}")
    print(f"  Low incidents       : {by_sev.get('low', 0)}")
    print()
    print("  Incident types:")
    for itype, cnt in sorted(by_typ.items(), key=lambda x: -x[1]):
        print(f"    {itype:<25} {cnt}")
    print()

    # ── Success criteria ───────────────────────────────────────────────────────
    print("-" * 50)
    print("  SUCCESS CRITERIA")
    print("-" * 50)
    checks = _validate(queue)
    all_pass = all(checks.values())
    status_str = {True: "PASS", False: "FAIL"}
    print(f"  Alert reduction >=40%   : {status_str[checks['alert_reduction_ge_40']]}  "
          f"({queue.alert_reduction_pct:.1f}%)")
    print(f"  Incidents >=20          : {status_str[checks['incidents_ge_20']]}  "
          f"({queue.total_incidents})")
    print(f"  All incidents MITRE   : {status_str[checks['all_mitre_mapped']]}")
    print(f"  All incidents evidence: {status_str[checks['all_have_evidence']]}")
    print()
    print(f"  Overall: {'ALL CRITERIA MET' if all_pass else 'SOME CRITERIA FAILED'}")
    print()

    # ── Save JSON ──────────────────────────────────────────────────────────────
    os.makedirs("outputs", exist_ok=True)
    out_path = os.path.join("outputs", "incidents.json")
    payload = {
        "generated_at":        datetime.utcnow().isoformat() + "Z",
        "alert_reduction_pct": queue.alert_reduction_pct,
        "total_raw_signals":   queue.total_raw_signals,
        "total_incidents":     queue.total_incidents,
        "success_criteria":    checks,
        "stats":               queue.stats,
        "incidents":           [_incident_to_dict(inc) for inc in queue.incidents],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    print(f"  Incidents saved to {out_path}")
    print()


if __name__ == "__main__":
    main()
