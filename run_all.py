"""
run_all.py — Full pipeline runner: Feature 1 then Feature 2.

Usage:
    python run_all.py
    python run_all.py --data-dir data/
"""
from __future__ import annotations

import sys
import time
import warnings
import argparse

# Force UTF-8 output so main.py's Unicode characters (checkmarks, bars, etc.)
# don't crash on Windows terminals defaulting to cp1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

warnings.filterwarnings("ignore", category=DeprecationWarning)

sys.path.insert(0, ".")

# ── sklearn shim (uses numpy; avoids requiring scikit-learn) ───────────────────
try:
    import sklearn.metrics  # noqa: F401 — use real sklearn if available
except ModuleNotFoundError:
    import types
    import numpy as _np

    def _accuracy_score(y_true, y_pred):
        yt, yp = _np.array(y_true), _np.array(y_pred)
        return float(_np.mean(yt == yp))

    def _precision_score(y_true, y_pred, zero_division=0):
        yt, yp = _np.array(y_true), _np.array(y_pred)
        tp = float(_np.sum((yp == 1) & (yt == 1)))
        fp = float(_np.sum((yp == 1) & (yt == 0)))
        return tp / (tp + fp) if (tp + fp) > 0 else float(zero_division)

    def _recall_score(y_true, y_pred, zero_division=0):
        yt, yp = _np.array(y_true), _np.array(y_pred)
        tp = float(_np.sum((yp == 1) & (yt == 1)))
        fn = float(_np.sum((yp == 0) & (yt == 1)))
        return tp / (tp + fn) if (tp + fn) > 0 else float(zero_division)

    def _f1_score(y_true, y_pred, zero_division=0):
        p = _precision_score(y_true, y_pred, zero_division)
        r = _recall_score(y_true, y_pred, zero_division)
        return 2 * p * r / (p + r) if (p + r) > 0 else float(zero_division)

    def _confusion_matrix(y_true, y_pred):
        yt, yp = _np.array(y_true), _np.array(y_pred)
        tn = int(_np.sum((yp == 0) & (yt == 0)))
        fp = int(_np.sum((yp == 1) & (yt == 0)))
        fn = int(_np.sum((yp == 0) & (yt == 1)))
        tp = int(_np.sum((yp == 1) & (yt == 1)))
        return _np.array([[tn, fp], [fn, tp]])

    _metrics = types.ModuleType("sklearn.metrics")
    _metrics.accuracy_score   = _accuracy_score
    _metrics.precision_score  = _precision_score
    _metrics.recall_score     = _recall_score
    _metrics.f1_score         = _f1_score
    _metrics.confusion_matrix = _confusion_matrix

    _sklearn = types.ModuleType("sklearn")
    _sklearn.metrics = _metrics
    sys.modules["sklearn"]         = _sklearn
    sys.modules["sklearn.metrics"] = _metrics

# ── CLI ────────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Run Feature 1 + Feature 2 in sequence")
parser.add_argument("--data-dir", default="data/", help="Path to data directory")
args = parser.parse_args()
DATA_DIR = args.data_dir

# ═══════════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("  RUN ALL — Ephemeral Cloud Risk Detection & Incident Correlation")
print("=" * 70)
print(f"  Data directory : {DATA_DIR}")
print(f"  Started at     : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
print("=" * 70)

# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 1 — Ingestion + Enrichment + Classification
# ═══════════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("  FEATURE 1 — Asset Discovery & Ephemeral Classification")
print("=" * 70)

from pipeline.ingestion import IngestionPipeline
from pipeline.enrichment import enrich
from classifier.ephemeral_classifier import EphemeralClassifier, ClassifierConfig

t_f1 = time.time()

print(f"\n  [1/3] Ingesting telemetry from '{DATA_DIR}'...", end="", flush=True)
pipeline = IngestionPipeline(data_dir=DATA_DIR)
pipeline.ingest()
print(f"  {len(pipeline.event_stream):,} events | "
      f"{len(pipeline.asset_registry):,} assets | "
      f"{len(pipeline.identity_registry):,} identities")

print("  [2/3] Enriching signals...", end="", flush=True)
enrich(pipeline)
print("  done")

print("  [3/3] Classifying entities...", end="", flush=True)
clf     = EphemeralClassifier(ClassifierConfig())
results = clf.classify_all(pipeline)
print(f"  {len(results):,} entities classified")

# ── Feature 1 test suite ───────────────────────────────────────────────────────
from main import run_tests
f1_all_pass = run_tests(pipeline, results, clf, DATA_DIR)
f1_elapsed  = round(time.time() - t_f1, 1)

# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 2 — Detection & Correlation Engine
# ═══════════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("  FEATURE 2 — Detection & Correlation Engine")
print("=" * 70)
print()

from detection.signal_scorer import score_all
from detection.burst_detector import detect_bursts
from detection.correlator import correlate
from detection.incident_queue import build_queue, top_evidence

t_f2 = time.time()

print("[1/4] Scoring risk signals...     ", end="", flush=True)
signals   = score_all(pipeline, results)
print(f"[OK] {len(signals)} signals detected")

print("[2/4] Detecting bursts...         ", end="", flush=True)
bursts    = detect_bursts(pipeline)
print(f"[OK] {len(bursts)} burst events")

print("[3/4] Correlating incidents...    ", end="", flush=True)
incidents = correlate(signals, bursts, pipeline)
print(f"[OK] {len(incidents)} incidents")

print("[4/4] Building incident queue...  ", end="", flush=True)
queue     = build_queue(incidents)
print(f"[OK] Alert reduction: {queue.alert_reduction_pct:.1f}%")
print()

f2_elapsed = round(time.time() - t_f2, 1)

# ── Formatting helpers ─────────────────────────────────────────────────────────
def _window_str(t0, t1) -> str:
    if t0 is None or t1 is None:
        return "??-??"
    if t0.date() == t1.date():
        return f"{t0.strftime('%H:%M')}-{t1.strftime('%H:%M')}"
    return f"{t0.strftime('%m/%d %H:%M')} to {t1.strftime('%m/%d %H:%M')}"

def _norm_score(score: float, severity: str) -> int:
    """Map raw incident_score to 0-100 int within the severity band."""
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

# ── Feature 2 automated test suite ────────────────────────────────────────────
def run_f2_tests(sigs, bsts, incs, q) -> bool:
    from detection.signal_scorer import SIGNAL_WEIGHTS
    SEP  = "-" * 70
    SEP2 = "=" * 70
    res = []

    print(f"\n{SEP2}")
    print("  FEATURE 2 - AUTOMATED TEST SUITE")
    print("  Detection & Correlation Engine")
    print(SEP2)

    # TEST 1 — Risk Signal Detection
    print(f"\n{SEP}")
    print("  TEST 1 - RISK SIGNAL DETECTION")
    print(SEP)
    active    = {s.signal_type for s in sigs} & set(SIGNAL_WEIGHTS.keys())
    scores_ok = all(
        abs(s.score - SIGNAL_WEIGHTS[s.signal_type]) < 1e-9
        for s in sigs if s.signal_type in SIGNAL_WEIGHTS
    )
    all_evid = all(bool(s.evidence) for s in sigs)
    print(f"  Total signals    : {len(sigs)}")
    for st in sorted(SIGNAL_WEIGHTS):
        cnt = sum(1 for s in sigs if s.signal_type == st)
        print(f"    {'[OK]' if cnt else '[--]'}  {st:<35} {cnt}")
    print(f"  Active types     : {len(active)}/{len(SIGNAL_WEIGHTS)}")
    print(f"  Scores match spec: {'[OK]' if scores_ok else '[FAIL]'}")
    print(f"  All have evidence: {'[OK]' if all_evid else '[FAIL]'}")
    t1 = len(sigs) > 0 and len(active) >= 5 and scores_ok and all_evid
    print(f"\n  {'[PASS]' if t1 else '[FAIL]'} TEST 1 - Risk Signal Detection")
    res.append(t1)

    # TEST 2 — Burst Detection
    print(f"\n{SEP}")
    print("  TEST 2 - BURST DETECTION")
    print(SEP)
    valid_sevs  = {"critical", "high", "medium", "low"}
    z_flagged   = sum(1 for b in bsts if b.zscore > 3)
    iqr_flagged = sum(1 for b in bsts if b.iqr_flag)
    sev_valid   = all(b.severity in valid_sevs for b in bsts)
    print(f"  Total burst events  : {len(bsts)}")
    print(f"  Namespaces covered  : {len({b.namespace for b in bsts})}")
    print(f"  Z-score flagged     : {z_flagged}")
    print(f"  IQR flagged         : {iqr_flagged}")
    print(f"  Severity labels OK  : {'[OK]' if sev_valid else '[FAIL]'}")
    t2 = len(bsts) > 0 and (z_flagged > 0 or iqr_flagged > 0) and sev_valid
    print(f"\n  {'[PASS]' if t2 else '[FAIL]'} TEST 2 - Burst Detection")
    res.append(t2)

    # TEST 3 — Correlation Engine
    print(f"\n{SEP}")
    print("  TEST 3 - CORRELATION ENGINE")
    print(SEP)
    bad_win   = [i for i in incs if i.time_window[0] > i.time_window[1]]
    all_mitre = all(len(i.mitre_techniques) > 0 for i in incs)
    total_s   = sum(len(i.signals) for i in incs)
    multi     = sum(1 for i in incs if len(i.signals) > 1)
    print(f"  Incidents created    : {len(incs)}  (target >= 20)")
    print(f"  Total signals in     : {total_s}")
    print(f"  Multi-signal incs    : {multi} ({100*multi//max(len(incs),1)}%)")
    print(f"  Invalid time windows : {len(bad_win)}  (expect 0)")
    print(f"  MITRE coverage       : {'[OK]' if all_mitre else '[FAIL]'}  {len(incs)}/{len(incs)}")
    t3 = len(incs) >= 20 and len(bad_win) == 0 and all_mitre
    print(f"\n  {'[PASS]' if t3 else '[FAIL]'} TEST 3 - Correlation Engine")
    res.append(t3)

    # TEST 4 — Noise Reduction
    print(f"\n{SEP}")
    print("  TEST 4 - NOISE REDUCTION")
    print(SEP)
    print(f"  Raw signals     : {q.total_raw_signals}")
    print(f"  Incidents       : {q.total_incidents}")
    print(f"  Alert reduction : {q.alert_reduction_pct:.1f}%  (target >= 40%)")
    t4 = q.alert_reduction_pct >= 40.0
    print(f"\n  {'[PASS]' if t4 else '[FAIL]'} TEST 4 - Noise Reduction")
    res.append(t4)

    # TEST 5 — Severity Ranking
    print(f"\n{SEP}")
    print("  TEST 5 - SEVERITY RANKING")
    print(SEP)
    sorted_ok  = all(
        q.incidents[i].incident_score >= q.incidents[i+1].incident_score
        for i in range(len(q.incidents)-1)
    )
    thresholds = {"critical": 1.2, "high": 0.8, "medium": 0.5}
    sev_ok = sev_bad = 0
    for inc in incs:
        exp = "low"
        for sv, thr in sorted(thresholds.items(), key=lambda x: -x[1]):
            if inc.incident_score >= thr:
                exp = sv
                break
        (sev_ok if inc.severity == exp else sev_bad)
        if inc.severity == exp:
            sev_ok += 1
        else:
            sev_bad += 1
    by_sev_t = q.stats.get("by_severity", {})
    print(f"  Sort order correct: {'[OK]' if sorted_ok else '[FAIL]'}")
    print(f"  Severity labelling: {sev_ok} correct / {sev_bad} wrong")
    print("  Distribution:")
    for sv in ("critical", "high", "medium", "low"):
        cnt = by_sev_t.get(sv, 0)
        bar = "#" * min(cnt // max(len(incs)//25, 1), 25)
        print(f"    {sv:<10} {cnt:>4}  {bar}")
    print("  Top 3 incidents:")
    for i, inc in enumerate(q.incidents[:3], 1):
        ns = _norm_score(inc.incident_score, inc.severity)
        print(f"    {i}. [{ns} {inc.severity.upper()}] score={inc.incident_score:.3f}  {inc.incident_id}")
    t5 = sorted_ok and sev_ok >= sev_bad
    print(f"\n  {'[PASS]' if t5 else '[FAIL]'} TEST 5 - Severity Ranking")
    res.append(t5)

    # TEST 6 — Evidence Generation
    print(f"\n{SEP}")
    print("  TEST 6 - EVIDENCE GENERATION")
    print(SEP)
    no_ev   = [i for i in incs if not top_evidence(i, n=1)]
    ev_lens = [len(s.evidence) for i in incs for s in i.signals if s.evidence]
    avg_l   = int(sum(ev_lens) / len(ev_lens)) if ev_lens else 0
    min_l   = min(ev_lens) if ev_lens else 0
    print(f"  Incidents missing evidence : {len(no_ev)}  (expect 0)")
    print(f"  Average evidence length    : {avg_l} chars")
    print(f"  Shortest evidence          : {min_l} chars")
    if q.incidents:
        print("  Sample (top incident):")
        for snip in top_evidence(q.incidents[0], n=3):
            short = snip[:85] + "..." if len(snip) > 85 else snip
            print(f"    * {short}")
    t6 = len(no_ev) == 0 and min_l >= 20
    print(f"\n  {'[PASS]' if t6 else '[FAIL]'} TEST 6 - Evidence Generation")
    res.append(t6)

    passed = sum(res)
    total  = len(res)
    print(f"\n{SEP2}")
    print(f"  FEATURE 2 TEST SUITE: {passed}/{total} PASSED")
    print(SEP2)
    return passed == total

# ── Feature 2 incident queue (top 10) ─────────────────────────────────────────
print("-" * 70)
print("  INCIDENT QUEUE (top 10)")
print("-" * 70)

for rank, inc in enumerate(queue.incidents[:10], 1):
    win = _window_str(inc.time_window[0], inc.time_window[1])
    sev = inc.severity.upper()
    ns  = _norm_score(inc.incident_score, inc.severity)
    print(f"\n  #{rank}  {inc.incident_id}  [{ns} {sev}]  {inc.incident_type}")
    print(f"  Raw Score: {inc.incident_score:.3f}  |  Signals: {len(inc.signals)}  |  Window: {win}")
    if inc.principals:
        suffix = f" +{len(inc.principals)-3} more" if len(inc.principals) > 3 else ""
        print(f"  Principals: {inc.principals[:3]}{suffix}")
    if inc.namespaces:
        print(f"  Namespaces: {inc.namespaces[:4]}")
    print(f"  MITRE: {', '.join(inc.mitre_techniques)}")
    if inc.burst_events:
        print(f"  Burst events associated: {len(inc.burst_events)}")
    print("  Evidence:")
    for snippet in top_evidence(inc, n=3):
        print(f"    * {snippet}")

# ── Feature 2 summary ──────────────────────────────────────────────────────────
print()
print("-" * 70)
print("  FEATURE 2 SUMMARY")
print("-" * 70)
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

# Run Feature 2 automated test suite
f2_all_pass = run_f2_tests(signals, bursts, incidents, queue)

# ═══════════════════════════════════════════════════════════════════════════════
#  COMBINED SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("  COMBINED SUMMARY")
print("=" * 70)
print()

f1_label = "8/8 tests PASS" if f1_all_pass else "SOME TESTS FAILED"
f2_label = (
    f"alert reduction {queue.alert_reduction_pct:.1f}%, "
    f"{queue.total_incidents} incidents  "
    f"[{'PASS' if f2_all_pass else 'FAIL'}]"
)
overall_pass = f1_all_pass and f2_all_pass

print(f"  Feature 1 : {f1_label}")
print(f"  Feature 2 : {f2_label}")
print()
print(f"  Overall   : {'READY FOR DEMO' if overall_pass else 'NEEDS ATTENTION'}")
print()
print(f"  Run time  : F1={f1_elapsed}s  |  F2={f2_elapsed}s  |  Total={round(f1_elapsed+f2_elapsed,1)}s")
print()
print("=" * 70)
print()
