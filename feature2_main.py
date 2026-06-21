from __future__ import annotations
import argparse, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
 
sys.path.insert(0, str(Path(__file__).parent))
 
from pipeline.ingestion import IngestionPipeline
from pipeline.enrichment import enrich
from classifier.ephemeral_classifier import EphemeralClassifier, ClassifierConfig
from detection.signal_scorer  import score_all
from detection.burst_detector import detect_bursts
from detection.correlator     import correlate
from detection.incident_queue import build_queue
 
RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
RED="\033[31m"; YEL="\033[33m"; GRN="\033[32m"; CYN="\033[36m"
SEP="─"*52; SEP2="═"*52
 
SCOL = {"CRITICAL":RED,"HIGH":YEL,"MEDIUM":CYN,"LOW":GRN}
 
 
def _fmt_window(tw):
    t_start, t_end = tw
    if not t_start or not t_end: return "unknown"
    try:
        if t_start.date() == t_end.date():
            return f"{t_start.strftime('%H:%M')}–{t_end.strftime('%H:%M')}"
        return f"{t_start.strftime('%m/%d %H:%M')}–{t_end.strftime('%m/%d %H:%M')}"
    except: return "unknown"
 
 
def _fmt_dur(dur_min):
    m = int(dur_min)
    if m < 60: return f"{m}min"
    return f"{m//60}h {m%60}min"
 
 
def _print_inc(rank, inc):
    sev   = getattr(inc,"severity","LOW")
    c     = SCOL.get(sev,"")
    itype = getattr(inc,"incident_type","mixed")
    score = getattr(inc,"incident_score",0.0)
    sigs  = getattr(inc,"signals",[])
    bursts= getattr(inc,"burst_events",[])
    tw    = getattr(inc,"time_window",(None,None))
    principals = getattr(inc,"principals",[])
    namespaces = getattr(inc,"namespaces",[])
    sources    = getattr(inc,"sources",[])
    mitre      = getattr(inc,"mitre_techniques",[])
    evidence   = getattr(inc,"evidence",[])
    inc_id     = getattr(inc,"incident_id","?")
    dur        = getattr(inc,"duration_minutes",0)
 
    print(f"\n  #{rank}  {BOLD}{inc_id}{RESET}  [{c}{BOLD}{sev}{RESET}]  {itype}")
    dur_str = _fmt_dur(dur) if dur > 0 else ""
    print(f"  Score: {score:.3f}  |  Signals: {len(sigs)}"
          + (f"  |  Bursts: {len(bursts)}" if bursts else "")
          + f"  |  Window: {_fmt_window(tw)}"
          + (f" ({dur_str})" if dur_str else ""))
 
    if principals:
        shown = principals[:2]
        more  = len(principals) - 2
        pstr  = ", ".join(f"'{p.split('/')[-1]}'" for p in shown)
        if more > 0: pstr += f" +{more} more"
        print(f"  Principals: {pstr}")
 
    if namespaces:
        print(f"  Namespaces: {', '.join(sorted(namespaces))}")
 
    if sources:
        print(f"  Sources: {', '.join(sorted(sources))}")
 
    if mitre:
        print(f"  MITRE: {', '.join(mitre)}")
 
    if evidence:
        print(f"  Evidence:")
        for ev in evidence[:3]:
            if ev: print(f"    • {ev}")
 
 
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="data/")
    parser.add_argument("--top",      default=10, type=int)
    parser.add_argument("--export",   default="outputs/incidents.json")
    args = parser.parse_args()
 
    print(f"\n{BOLD}{SEP2}{RESET}")
    print(f"{BOLD}  FEATURE 2 — DETECTION & CORRELATION ENGINE{RESET}")
    print(f"{BOLD}{SEP2}{RESET}\n")
 
    print(f"  {DIM}Loading Feature 1 pipeline...{RESET}", end="", flush=True)
    pipeline = IngestionPipeline(data_dir=args.data_dir)
    pipeline.ingest()
    enrich(pipeline)
    clf     = EphemeralClassifier(ClassifierConfig())
    results = clf.classify_all(pipeline)
    print(f" {GRN}✓{RESET}  {len(pipeline.asset_registry)} assets | "
          f"{len(pipeline.identity_registry)} identities | "
          f"{len(pipeline.event_stream)} events")
 
    print(f"  {DIM}[1/3] Scoring risk signals...{RESET}", end="", flush=True)
    signals = score_all(pipeline, results)
    print(f"     {GRN}✓{RESET}  {len(signals)} signals  "
          f"(audit={sum(1 for s in signals if s.source=='cloud_audit')} | "
          f"k8s={sum(1 for s in signals if s.source=='k8s')} | "
          f"identity={sum(1 for s in signals if s.source=='identity')})")
 
    print(f"  {DIM}[2/3] Detecting bursts...{RESET}", end="", flush=True)
    bursts = detect_bursts(pipeline)
    print(f"        {GRN}✓{RESET}  {len(bursts)} burst events")
 
    print(f"  {DIM}[3/3] Correlating incidents...{RESET}", end="", flush=True)
    incidents = correlate(signals, bursts, pipeline)
    queue     = build_queue(incidents, raw_signal_count=len(signals))
    print(f"    {GRN}✓{RESET}  {queue.total_incidents} incidents  |  "
          f"Alert reduction: {GRN}{BOLD}{queue.alert_reduction_pct}%{RESET}")
 
    print(f"\n{BOLD}{SEP}{RESET}")
    print(f"{BOLD}  INCIDENT QUEUE  (top {args.top}){RESET}")
    print(f"{BOLD}{SEP}{RESET}")
 
    for i, inc in enumerate(queue.incidents[:args.top], 1):
        _print_inc(i, inc)
 
    print(f"\n{BOLD}{SEP}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{BOLD}{SEP}{RESET}")
    by_sev  = queue.stats.get("by_severity",{})
    by_type = queue.stats.get("by_incident_type",{})
 
    print(f"\n  Total raw signals   : {queue.total_raw_signals}")
    print(f"  Incidents created   : {queue.total_incidents}")
    print(f"  Alert reduction     : {GRN}{BOLD}{queue.alert_reduction_pct}%{RESET}  (target ≥40%)")
    print(f"\n  {RED}Critical{RESET}  : {by_sev.get('CRITICAL',0)}")
    print(f"  {YEL}High{RESET}      : {by_sev.get('HIGH',0)}")
    print(f"  {CYN}Medium{RESET}    : {by_sev.get('MEDIUM',0)}")
    print(f"  {GRN}Low{RESET}       : {by_sev.get('LOW',0)}")
    if by_type:
        print()
        for itype, cnt in sorted(by_type.items(), key=lambda x:-x[1]):
            print(f"  {itype:<25} {cnt}")
 
    # Export
    os.makedirs(os.path.dirname(args.export) if os.path.dirname(args.export) else ".", exist_ok=True)
 
    def _ser(inc):
        tw = getattr(inc,"time_window",(None,None))
        return {
            "incident_id":      getattr(inc,"incident_id",""),
            "incident_type":    getattr(inc,"incident_type",""),
            "severity":         getattr(inc,"severity",""),
            "incident_score":   getattr(inc,"incident_score",0),
            "signal_count":     len(getattr(inc,"signals",[])),
            "burst_count":      len(getattr(inc,"burst_events",[])),
            "duration_minutes": getattr(inc,"duration_minutes",0),
            "principals":       getattr(inc,"principals",[]),
            "namespaces":       getattr(inc,"namespaces",[]),
            "sources":          getattr(inc,"sources",[]),
            "mitre_techniques": getattr(inc,"mitre_techniques",[]),
            "evidence":         getattr(inc,"evidence",[]),
            "correlation_ids":  getattr(inc,"correlation_ids",[]),
            "time_window": {
                "start": tw[0].isoformat() if tw[0] else None,
                "end":   tw[1].isoformat() if tw[1] else None,
            },
        }
 
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_raw_signals":   queue.total_raw_signals,
            "total_incidents":     queue.total_incidents,
            "alert_reduction_pct": queue.alert_reduction_pct,
            "by_severity":         by_sev,
            "by_incident_type":    by_type,
        },
        "incidents": [_ser(i) for i in queue.incidents],
    }
 
    with open(args.export, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  {DIM}Saved to {args.export}{RESET}\n")
 
 
if __name__ == "__main__":
    main()