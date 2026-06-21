"""
feature4_main.py
────────────────
Feature 4: LLM Narrative Generation
 
Runs Feature 1 + 2 pipeline, then generates analyst narratives
for top incidents using Google groq API (free tier).
 
Usage:
    python feature4_main.py --data-dir data/ --api-key YOUR_KEY
    python feature4_main.py --data-dir data/ --top 20
    python feature4_main.py --data-dir data/ --no-api   (rule-based only)
 
Set API key via environment variable (recommended):
    set GROQ_API_KEY=your_key_here        (Windows)
    export GROQ_API_KEY=your_key_here     (Linux/Mac)
"""
 
from __future__ import annotations
 
import argparse
import os
import sys
from pathlib import Path
 
sys.path.insert(0, str(Path(__file__).parent))
 
# ── Feature 1 ──────────────────────────────────────────────────────────────────
from pipeline.ingestion import IngestionPipeline
from pipeline.enrichment import enrich
from classifier.ephemeral_classifier import EphemeralClassifier, ClassifierConfig
 
# ── Feature 2 ──────────────────────────────────────────────────────────────────
from detection.signal_scorer  import score_all
from detection.burst_detector import detect_bursts
from detection.correlator     import correlate
from detection.incident_queue import build_queue
 
# ── Feature 4 ──────────────────────────────────────────────────────────────────
from narrative.narrator import generate_narratives
 
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED   = "\033[31m"; YEL  = "\033[33m"; GRN = "\033[32m"; CYN = "\033[36m"
SEP2  = "═" * 52
SEP   = "─" * 52
 
CONF_COLOR = {"high": GRN, "medium": YEL, "low": RED}
SEV_COLOR  = {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": CYN, "LOW": GRN}
 
 
def _print_narrative(rank: int, narrative, inc=None) -> None:
    sev_c  = SEV_COLOR.get(narrative.severity, "")
    conf_c = CONF_COLOR.get(narrative.confidence, "")
 
    print(f"\n  {'─'*50}")
    print(f"  #{rank}  {BOLD}{narrative.incident_id}{RESET}  "
          f"[{sev_c}{BOLD}{narrative.severity}{RESET}]  {narrative.incident_type}")
    print(f"  Confidence: {conf_c}{narrative.confidence.upper()}{RESET}  |  "
          f"Model: {DIM}{narrative.model}{RESET}")
 
    print(f"\n  {BOLD}SUMMARY{RESET}")
    # Word-wrap summary at 70 chars
    words = narrative.summary.split()
    line = "  "
    for word in words:
        if len(line) + len(word) > 72:
            print(line)
            line = "    " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)
 
    print(f"\n  {BOLD}LIKELY INTENT{RESET}")
    print(f"    {narrative.likely_intent}")
 
    if narrative.evidence_chain:
        print(f"\n  {BOLD}EVIDENCE CHAIN{RESET}")
        for i, ev in enumerate(narrative.evidence_chain, 1):
            print(f"    {i}. {ev}")
 
    if narrative.mitre_mapping:
        print(f"\n  {BOLD}MITRE ATT&CK MAPPING{RESET}")
        for tech, desc in narrative.mitre_mapping.items():
            print(f"    {YEL}{tech}{RESET}  —  {desc}")
 
    if narrative.guardrails:
        print(f"\n  {BOLD}RECOMMENDED GUARDRAILS{RESET}")
        for i, gr in enumerate(narrative.guardrails, 1):
            print(f"    {GRN}{i}.{RESET} {gr}")
 
 
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Feature 4 — LLM Narrative Generation"
    )
    parser.add_argument("--data-dir",  default="data/",
                        help="Directory with CSV files")
    parser.add_argument("--api-key",   default="",
                        help="Groq API key (or set GROQ_API_KEY env var)")
    parser.add_argument("--top",       default=16, type=int,
                        help="Number of incidents to generate narratives for")
    parser.add_argument("--no-api",    action="store_true",
                        help="Use rule-based fallback only (no API call)")
    parser.add_argument("--export",    default="outputs/narratives.json",
                        help="Output path for narratives JSON")
    args = parser.parse_args()
 
    # API key priority: --api-key flag > env var > empty (fallback mode)
    api_key = args.api_key or os.environ.get("GROQ_API_KEY", "")
    if args.no_api:
        api_key = ""
 
    print(f"\n{BOLD}{SEP2}{RESET}")
    print(f"{BOLD}  FEATURE 4 — LLM NARRATIVE GENERATION{RESET}")
    print(f"{BOLD}{SEP2}{RESET}\n")
 
    mode = "GROQ API" if (api_key and not args.no_api) else "Rule-based fallback"
    print(f"  Mode: {BOLD}{mode}{RESET}")
    if not api_key and not args.no_api:
        print(f"  {YEL}⚠  No API key found — using rule-based narratives{RESET}")
        print(f"     Set key: set GROQ_API_KEY=your_key  (Windows)")
        print(f"     Or pass: --api-key YOUR_KEY")
 
    # ── Feature 1 ──────────────────────────────────────────────────────────────
    print(f"\n  {DIM}Loading Feature 1 pipeline...{RESET}", end="", flush=True)
    pipeline = IngestionPipeline(data_dir=args.data_dir)
    pipeline.ingest()
    enrich(pipeline)
    clf     = EphemeralClassifier(ClassifierConfig())
    results = clf.classify_all(pipeline)
    print(f" {GRN}✓{RESET}  {len(pipeline.asset_registry)} assets | "
          f"{len(pipeline.identity_registry)} identities")
 
    # ── Feature 2 ──────────────────────────────────────────────────────────────
    print(f"  {DIM}Running detection engine...{RESET}", end="", flush=True)
    signals   = score_all(pipeline, results)
    bursts    = detect_bursts(pipeline)
    incidents = correlate(signals, bursts, pipeline)
    queue     = build_queue(incidents, raw_signal_count=len(signals))
    print(f"   {GRN}✓{RESET}  {len(incidents)} incidents | "
          f"Alert reduction: {queue.alert_reduction_pct:.1f}%")
 
    # ── Feature 4 ──────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{SEP}{RESET}")
    print(f"{BOLD}  GENERATING NARRATIVES{RESET}")
    print(f"{BOLD}{SEP}{RESET}")
 
    narratives = generate_narratives(
        incidents   = queue.incidents,
        api_key     = api_key,
        top_n       = args.top,
        output_path = args.export,
    )
 
    # ── Print narratives ────────────────────────────────────────────────────────
    print(f"\n{BOLD}{SEP}{RESET}")
    print(f"{BOLD}  INCIDENT NARRATIVES{RESET}")
    print(f"{BOLD}{SEP}{RESET}")
 
    for i, narrative in enumerate(narratives[:5], 1):
        _print_narrative(i, narrative)
 
    if len(narratives) > 5:
        print(f"\n  {DIM}... {len(narratives)-5} more narratives saved to {args.export}{RESET}")
 
    # ── Summary ─────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{SEP}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{BOLD}{SEP}{RESET}")
 
    by_conf = {"high": 0, "medium": 0, "low": 0}
    for n in narratives:
        by_conf[n.confidence] = by_conf.get(n.confidence, 0) + 1
 
    print(f"\n  Narratives generated : {len(narratives)}")
    print(f"  {GRN}High confidence{RESET}      : {by_conf['high']}")
    print(f"  {YEL}Medium confidence{RESET}    : {by_conf['medium']}")
    print(f"  {RED}Low confidence{RESET}       : {by_conf['low']}")
    print(f"\n  Saved to             : {args.export}")
    print(f"  Ready for dashboard  : run python feature3_main.py\n")
 
 
if __name__ == "__main__":
    main()
 


































