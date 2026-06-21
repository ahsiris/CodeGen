"""
narrative/narrator.py
─────────────────────
Feature 4: LLM Narrative Generation
 
Uses GROQ API (free tier) to generate analyst-ready
incident narratives for every CRITICAL and HIGH incident.
 
Each narrative contains:
  - summary        : 2-sentence description of what happened
  - likely_intent  : what the attacker was trying to achieve
  - evidence_chain : ordered bullet list of observed signals
  - mitre_mapping  : technique → specific observed behavior
  - guardrails     : 3 concrete remediation recommendations
  - confidence     : high / medium / low
 
Output saved to outputs/narratives.json for dashboard consumption.
 
Usage:
    python feature4_main.py --data-dir data/
    python feature4_main.py --data-dir data/ --top 20
"""
 
from __future__ import annotations
 
import json
import os
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
 
import requests
 
# ──GROQ API config ──────────────────────────────────────────────────────────
 
GROQ_API_KEY    = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL      = "llama-3.3-70b-versatile"
GROQ_ENDPOINT   = "https://api.groq.com/openai/v1/chat/completions"
REQUEST_DELAY   = 2.0

MITRE_DESC = {
    "T1190": "Exploit Public-Facing Application",
    "T1610": "Deploy Container",
    "T1078": "Valid Accounts — credential abuse or session hijacking",
    "T1496": "Resource Hijacking — crypto mining or compute abuse",
    "T1036": "Masquerading — untagged or mislabeled resources",
}
 
 
# ── Narrative dataclass ────────────────────────────────────────────────────────
 
@dataclass
class IncidentNarrative:
    incident_id:    str
    severity:       str
    incident_type:  str
    summary:        str
    likely_intent:  str
    evidence_chain: list[str]
    mitre_mapping:  dict[str, str]
    guardrails:     list[str]
    confidence:     str
    generated_at:   str
    model:          str
 
 
# ── Prompt builder ─────────────────────────────────────────────────────────────
 
def _build_prompt(inc) -> str:
    tw        = getattr(inc, "time_window", (None, None))
    t_start   = tw[0].strftime("%Y-%m-%d %H:%M UTC") if tw[0] else "unknown"
    t_end     = tw[1].strftime("%Y-%m-%d %H:%M UTC") if tw[1] else "unknown"
    duration  = getattr(inc, "duration_minutes", 0)
    principals= getattr(inc, "principals", [])
    namespaces= getattr(inc, "namespaces", [])
    mitre     = getattr(inc, "mitre_techniques", [])
    evidence  = getattr(inc, "evidence", [])
    itype     = getattr(inc, "incident_type", "mixed")
    severity  = getattr(inc, "severity", "HIGH")
    score     = getattr(inc, "incident_score", 0.0)
    sources   = getattr(inc, "sources", [])
 
    mitre_lines = "\n".join(
        f"  - {t}: {MITRE_DESC.get(t, 'Unknown technique')}"
        for t in mitre
    )
    evidence_lines = "\n".join(f"  - {e}" for e in evidence[:5])
    principal_str  = ", ".join(
        p.split("/")[-1] for p in principals[:4]
    ) or "unknown"
    ns_str         = ", ".join(namespaces[:4]) or "unknown"
    source_str     = ", ".join(sorted(sources)) or "cloud_audit"
 
    return f"""You are a senior cloud security analyst writing an incident report for a SOC team.
 
INCIDENT DATA:
  Incident ID    : {getattr(inc, 'incident_id', '?')}
  Severity       : {severity}
  Type           : {itype}
  Risk Score     : {score:.3f}
  Time Window    : {t_start} to {t_end}
  Duration       : {duration:.0f} minutes
  Principals     : {principal_str}
  Namespaces     : {ns_str}
  Data Sources   : {source_str}
  Signal Count   : {len(getattr(inc, 'signals', []))}
 
MITRE ATT&CK TECHNIQUES DETECTED:
{mitre_lines}
 
EVIDENCE OBSERVED:
{evidence_lines}
 
Write a concise, professional incident narrative in valid JSON format.
Return ONLY the JSON object, no markdown, no backticks, no preamble.
 
Required JSON structure:
{{
  "summary": "Two sentences. Sentence 1: what happened and when. Sentence 2: the scope and immediate risk.",
  "likely_intent": "One sentence describing what the attacker was most likely trying to achieve.",
  "evidence_chain": [
    "First observed indicator (earliest timestamp)",
    "Second indicator showing escalation",
    "Third indicator confirming attack pattern",
    "Fourth indicator showing impact or exfiltration attempt"
  ],
  "mitre_mapping": {{
    "T1190": "Specific behavior that triggered this technique in this incident",
    "T1078": "Specific behavior that triggered this technique in this incident"
  }},
  "guardrails": [
    "Specific remediation step 1 — actionable and concrete",
    "Specific remediation step 2 — preventive control",
    "Specific remediation step 3 — detection improvement"
  ],
  "confidence": "high"
}}
 
Confidence should be:
  high   — clear attack pattern, multiple corroborating signals, known MITRE technique
  medium — suspicious behavior but some ambiguity, could be misconfiguration
  low    — anomalous but limited evidence, requires analyst review
 
Write for a SOC analyst who will act on this report. Be specific, not generic."""
 
 
# ── Groq API call ────────────────────────────────────────────────────────────
 
def _call_groq(prompt: str, api_key: str) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 1024,
    }
    resp = requests.post(GROQ_ENDPOINT, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()

    raw_text = (
        resp.json()["choices"][0]["message"]["content"]
        .strip()
        .removeprefix("```json")
        .removeprefix("```")
        .removesuffix("```")
        .strip()
    )
    return json.loads(raw_text)
# ── Fallback narrative (if API fails) ─────────────────────────────────────────
 
def _fallback_narrative(inc) -> dict[str, Any]:
    """Generate a rule-based narrative when API is unavailable."""
    itype    = getattr(inc, "incident_type", "mixed")
    mitre    = getattr(inc, "mitre_techniques", [])
    evidence = getattr(inc, "evidence", [])
    tw       = getattr(inc, "time_window", (None, None))
    dur      = getattr(inc, "duration_minutes", 0)
    principals = getattr(inc, "principals", [])
    p_name   = principals[0].split("/")[-1] if principals else "unknown principal"
 
    summaries = {
        "resource_hijacking": (
            f"A high-privilege principal ({p_name}) created multiple ephemeral "
            f"compute resources with public IPs during off-hours over a {dur:.0f}-minute window. "
            f"This pattern is consistent with unauthorized crypto mining or compute resource abuse."
        ),
        "public_exposure":    (
            f"Ephemeral cloud and Kubernetes resources were exposed to the public internet "
            f"without proper access controls over {dur:.0f} minutes. "
            f"Short-lived exposed assets create a window for exploitation before remediation."
        ),
        "identity_abuse":     (
            f"Suspicious identity activity detected — {p_name} performed high-privilege "
            f"operations outside business hours using federated credentials over {dur:.0f} minutes. "
            f"This may indicate credential compromise or unauthorized access."
        ),
        "mixed": (
            f"Multiple correlated risk signals detected across cloud, Kubernetes, and identity "
            f"sources over {dur:.0f} minutes involving principal {p_name}. "
            f"The combination of off-hours activity, ephemeral resources, and public exposure "
            f"indicates a potential security incident requiring investigation."
        ),
    }
 
    intents = {
        "resource_hijacking": "The attacker likely aimed to use compromised cloud credentials to provision compute resources for cryptocurrency mining at the victim's expense.",
        "public_exposure":    "The actor may have intentionally or accidentally exposed resources to enable external access, reconnaissance, or data exfiltration.",
        "identity_abuse":     "The attacker likely used stolen or compromised credentials to access sensitive resources, potentially to exfiltrate data or establish persistence.",
        "mixed":              "The attacker appears to have used compromised credentials to provision ephemeral resources and establish unauthorized access across multiple cloud services.",
    }
 
    guardrail_map = {
        "resource_hijacking": [
            "Enable AWS Cost Anomaly Detection with alerts for >$100/hour spend spikes",
            "Enforce MFA for all AssumeRole API calls via IAM condition keys",
            "Implement tag enforcement policy via AWS Config — deny resource creation without required tags",
        ],
        "public_exposure": [
            "Block NodePort and LoadBalancer services in production namespaces via Kubernetes NetworkPolicy",
            "Enable VPC Flow Logs and alert on unexpected inbound connections to ephemeral instances",
            "Implement Pod Security Standards (restricted profile) across all non-dev namespaces",
        ],
        "identity_abuse": [
            "Enforce maximum session duration of 1 hour for all assumed-role sessions via IAM role policy",
            "Enable CloudTrail with real-time alerts for AssumeRole events outside business hours",
            "Implement just-in-time access via AWS IAM Identity Center — eliminate standing high-privilege roles",
        ],
        "mixed": [
            "Enforce MFA and session duration limits for all federated identity providers",
            "Enable CloudTrail, VPC Flow Logs, and K8s audit logs with centralized SIEM ingestion",
            "Implement tag enforcement and pod security standards across all namespaces",
        ],
    }
 
    mitre_mapping = {
        t: MITRE_DESC.get(t, "Unknown technique") + " — detected in this incident"
        for t in mitre
    }
 
    evidence_chain = [e[:120] for e in evidence[:4]] if evidence else [
        "Ephemeral resource created with high-privilege credentials",
        "Off-hours activity detected outside business hours",
        "Public IP assigned to short-lived resource",
        "Multiple correlated signals grouped into single incident",
    ]
 
    return {
        "summary":        summaries.get(itype, summaries["mixed"]),
        "likely_intent":  intents.get(itype, intents["mixed"]),
        "evidence_chain": evidence_chain,
        "mitre_mapping":  mitre_mapping,
        "guardrails":     guardrail_map.get(itype, guardrail_map["mixed"]),
        "confidence":     "medium",
    }
 
 
# ── Main narrator function ─────────────────────────────────────────────────────
 
def generate_narratives(
    incidents:   list,
    api_key:     str  = "",
    top_n:       int  = 20,
    output_path: str  = "outputs/narratives.json",
) -> list[IncidentNarrative]:
    """
    Generate LLM narratives for the top-N incidents by severity/score.
 
    Parameters
    ──────────
    incidents   : list[Incident] from correlator.correlate()
    api_key     : Groq API key (or set GROQ_API_KEY env var)
    top_n       : how many incidents to generate narratives for
    output_path : where to save the JSON output
 
    Returns
    ───────
    list[IncidentNarrative]
    """
    key = api_key or GROQ_API_KEY
    use_api = bool(key and key != "YOUR_GROQ_API_KEY_HERE")
 
    # Prioritise CRITICAL then HIGH, then by score
    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_incs = sorted(
        incidents,
        key=lambda i: (
            priority.get(getattr(i, "severity", "LOW"), 3),
            -getattr(i, "incident_score", 0),
        ),
    )[:top_n]
 
    narratives: list[IncidentNarrative] = []
    total = len(sorted_incs)
 
    print(f"\n  Generating narratives for {total} incidents "
          f"({'Groq API' if use_api else 'rule-based fallback'})...\n")
 
    for idx, inc in enumerate(sorted_incs, 1):
        inc_id   = getattr(inc, "incident_id", f"INC-{idx:04d}")
        severity = getattr(inc, "severity", "LOW")
        itype    = getattr(inc, "incident_type", "mixed")
        mitre    = getattr(inc, "mitre_techniques", [])
 
        print(f"  [{idx:2d}/{total}] {inc_id}  [{severity}]  {itype}", end="", flush=True)
 
        try:
            if use_api:
                prompt   = _build_prompt(inc)
                llm_data = _call_groq(prompt, key)
                model    = GROQ_MODEL
                time.sleep(REQUEST_DELAY)
            else:
                llm_data = _fallback_narrative(inc)
                model    = "rule-based-fallback"
 
            narrative = IncidentNarrative(
                incident_id    = inc_id,
                severity       = severity,
                incident_type  = itype,
                summary        = llm_data.get("summary", ""),
                likely_intent  = llm_data.get("likely_intent", ""),
                evidence_chain = llm_data.get("evidence_chain", []),
                mitre_mapping  = llm_data.get("mitre_mapping", {}),
                guardrails     = llm_data.get("guardrails", []),
                confidence     = llm_data.get("confidence", "medium"),
                generated_at   = datetime.now(timezone.utc).isoformat(),
                model          = model,
            )
            print(f"  ✓  (confidence={narrative.confidence})")
 
        except Exception as e:
            print(f"  ⚠  API error: {e} — using fallback")
            fallback = _fallback_narrative(inc)
            narrative = IncidentNarrative(
                incident_id    = inc_id,
                severity       = severity,
                incident_type  = itype,
                summary        = fallback["summary"],
                likely_intent  = fallback["likely_intent"],
                evidence_chain = fallback["evidence_chain"],
                mitre_mapping  = fallback["mitre_mapping"],
                guardrails     = fallback["guardrails"],
                confidence     = "low",
                generated_at   = datetime.now(timezone.utc).isoformat(),
                model          = "rule-based-fallback",
            )
 
        narratives.append(narrative)
 
    # Save to JSON
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model":        GROQ_MODEL if use_api else "rule-based-fallback",
        "total":        len(narratives),
        "narratives":   [asdict(n) for n in narratives],
    }
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
 
    print(f"\n  Saved {len(narratives)} narratives to {output_path}")
    return narratives