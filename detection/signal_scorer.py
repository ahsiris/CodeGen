"""
signal_scorer.py — Risk signal detection across assets, identities, and events.

Each signal maps to a specific threat pattern and MITRE technique.
score_all(pipeline, results) → list[RiskSignal]
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict
from typing import List

# ── Signal weight catalogue ────────────────────────────────────────────────────
SIGNAL_WEIGHTS: dict[str, float] = {
    "public_ip_on_ephemeral":        0.90,   # T1190
    "privileged_no_controller":      0.85,   # T1610
    "off_hours_assume_role":         0.75,   # T1078
    "burst_threshold_exceeded":      0.70,   # T1496
    "novel_principal_high_priv":     0.80,   # T1078
    "untagged_ephemeral":            0.50,   # (attribution loss)
    "cross_namespace_access":        0.60,   # lateral movement indicator
    "short_lived_high_priv_session": 0.75,   # T1078
}

# ── Event-type patterns that indicate role / credential acquisition ────────────
_ROLE_EVENT_TYPES: frozenset[str] = frozenset({
    "AssumeRole",
    "FederationLogin",
    "ConsoleLogin",
    "GetFederationToken",
    "AssumeRoleWithWebIdentity",
    "AssumeRoleWithSAML",
    "GetSessionToken",
    "TokenIssued",
})


@dataclass
class RiskSignal:
    """One detected risk signal for a single entity."""
    signal_id:      str
    entity_id:      str
    signal_type:    str
    score:          float
    evidence:       str
    timestamp:      datetime
    # Optional correlation axes (used by correlator)
    principal_id:   str = ""
    namespace:      str = ""
    source_ip:      str = ""
    correlation_id: str = ""


# ── Internal helpers ───────────────────────────────────────────────────────────

def _sid() -> str:
    return uuid.uuid4().hex[:8].upper()


def _is_off_hours(ts: datetime) -> bool:
    """True when ts falls in the 20:00-06:00 UTC window."""
    return ts.hour >= 20 or ts.hour < 6


def _is_role_event(event_type: str) -> bool:
    return event_type in _ROLE_EVENT_TYPES or any(
        kw in event_type.lower() for kw in ("assume", "federat", "login", "token")
    )


def _first_src_ip(ips: set[str]) -> str:
    return next((ip for ip in ips if ip and ip != "internal"), "")


# ── Main scorer ────────────────────────────────────────────────────────────────

def score_all(pipeline, results) -> List[RiskSignal]:
    """
    Score every observable risk signal across assets, identities, and events.

    Args:
        pipeline: IngestionPipeline (post-ingest + enrich)
        results:  dict[entity_id, ClassificationResult] from EphemeralClassifier

    Returns:
        List of RiskSignal objects, one per detected pattern.
    """
    signals: List[RiskSignal] = []

    # Pre-build correlation_id lookup from event stream
    # (avoid O(n) scan per asset/identity)
    resource_corr: dict[str, str] = {}
    principal_corr: dict[str, str] = {}
    for ev in pipeline.event_stream:
        cid = ev.correlation_id or ""
        if cid:
            if ev.resource_id and ev.resource_id not in resource_corr:
                resource_corr[ev.resource_id] = cid
            if ev.principal and ev.principal not in ("system", "inventory-scanner"):
                if ev.principal not in principal_corr:
                    principal_corr[ev.principal] = cid

    # ── Asset-based signals ────────────────────────────────────────────────────
    for resource_id, asset in pipeline.asset_registry.items():
        ttl = asset.ttl_seconds          # seconds, may be None
        ns  = asset.namespace or ""
        ts  = asset.last_seen or asset.first_seen
        if ts is None:
            continue                     # no timestamp — skip

        corr = resource_corr.get(resource_id, "")

        public_ip       = asset.public_ip
        privileged      = asset.privileged
        controller      = asset.controller
        tag_completeness = getattr(asset, "tag_completeness", 1.0)
        burst_activity  = getattr(asset, "burst_activity", False)

        # 1. public_ip_on_ephemeral
        if public_ip and ttl is not None and ttl < 3600:
            signals.append(RiskSignal(
                signal_id=_sid(),
                entity_id=resource_id,
                signal_type="public_ip_on_ephemeral",
                score=SIGNAL_WEIGHTS["public_ip_on_ephemeral"],
                evidence=(
                    f"{asset.resource_type} '{resource_id}' has public IP {public_ip} "
                    f"with ephemeral TTL {int(ttl)//60}min in ns:'{ns}'"
                ),
                timestamp=ts,
                namespace=ns,
                correlation_id=corr,
            ))

        # 2. privileged_no_controller
        if privileged and not controller:
            signals.append(RiskSignal(
                signal_id=_sid(),
                entity_id=resource_id,
                signal_type="privileged_no_controller",
                score=SIGNAL_WEIGHTS["privileged_no_controller"],
                evidence=(
                    f"{asset.resource_type} '{resource_id}' runs privileged with no "
                    f"controller parent in ns:'{ns}' — unmanaged root access"
                ),
                timestamp=ts,
                namespace=ns,
                correlation_id=corr,
            ))

        # 3. burst_threshold_exceeded  (enrichment already flagged this asset)
        if burst_activity:
            burst_groups = getattr(asset, "burst_groups", [])
            group_str = ", ".join(burst_groups[:2]) if burst_groups else "multiple events"
            signals.append(RiskSignal(
                signal_id=_sid(),
                entity_id=resource_id,
                signal_type="burst_threshold_exceeded",
                score=SIGNAL_WEIGHTS["burst_threshold_exceeded"],
                evidence=(
                    f"{asset.resource_type} '{resource_id}' in ns:'{ns}' triggered burst "
                    f"detection ({group_str}) — event rate exceeded 3σ baseline"
                ),
                timestamp=ts,
                namespace=ns,
                correlation_id=corr,
            ))

        # 4. untagged_ephemeral
        if tag_completeness == 0.0 and ttl is not None and ttl < 1800:
            signals.append(RiskSignal(
                signal_id=_sid(),
                entity_id=resource_id,
                signal_type="untagged_ephemeral",
                score=SIGNAL_WEIGHTS["untagged_ephemeral"],
                evidence=(
                    f"{asset.resource_type} '{resource_id}' has zero tag coverage "
                    f"and TTL {int(ttl)//60}min — unattributable ephemeral resource in ns:'{ns}'"
                ),
                timestamp=ts,
                namespace=ns,
                correlation_id=corr,
            ))

    # ── Identity-based signals ─────────────────────────────────────────────────
    for principal, identity in pipeline.identity_registry.items():
        is_novel        = identity.is_novel
        privilege_level = identity.privilege_level
        session_ttl     = identity.session_ttl_seconds
        namespaces_set  = identity.namespaces or set()
        source_ips_set  = identity.source_ips or set()
        ns  = identity.namespace or ""
        ts  = identity.last_seen or identity.first_seen
        if ts is None:
            continue

        corr   = principal_corr.get(principal, "")
        src_ip = _first_src_ip(source_ips_set)

        # 5. novel_principal_high_priv
        if is_novel and privilege_level in ("high", "critical"):
            signals.append(RiskSignal(
                signal_id=_sid(),
                entity_id=principal,
                signal_type="novel_principal_high_priv",
                score=SIGNAL_WEIGHTS["novel_principal_high_priv"],
                evidence=(
                    f"Novel principal '{principal}' with {privilege_level} privilege "
                    f"seen for the first time — possible lateral movement or new threat actor"
                ),
                timestamp=ts,
                principal_id=principal,
                namespace=ns,
                source_ip=src_ip,
                correlation_id=corr,
            ))

        # 6. cross_namespace_access
        if len(namespaces_set) > 3:
            ns_preview = ", ".join(sorted(namespaces_set)[:5])
            signals.append(RiskSignal(
                signal_id=_sid(),
                entity_id=principal,
                signal_type="cross_namespace_access",
                score=SIGNAL_WEIGHTS["cross_namespace_access"],
                evidence=(
                    f"Principal '{principal}' active in {len(namespaces_set)} namespaces: "
                    f"{ns_preview} — abnormal blast radius suggests privilege abuse"
                ),
                timestamp=ts,
                principal_id=principal,
                namespace=ns,
                source_ip=src_ip,
                correlation_id=corr,
            ))

        # 7. short_lived_high_priv_session
        if session_ttl is not None and session_ttl < 900 and privilege_level in ("high", "critical"):
            signals.append(RiskSignal(
                signal_id=_sid(),
                entity_id=principal,
                signal_type="short_lived_high_priv_session",
                score=SIGNAL_WEIGHTS["short_lived_high_priv_session"],
                evidence=(
                    f"Principal '{principal}' used a {privilege_level}-privilege session "
                    f"of only {int(session_ttl)//60}min — hit-and-run escalation pattern"
                ),
                timestamp=ts,
                principal_id=principal,
                namespace=ns,
                source_ip=src_ip,
                correlation_id=corr,
            ))

    # ── Event-based signals ────────────────────────────────────────────────────
    # Deduplicate off-hours role events per (principal, event_type, hour-bucket)
    _seen_off_hours: set[tuple] = set()

    for event in pipeline.event_stream:
        if not _is_role_event(event.event_type):
            continue
        ts = event.timestamp
        if not _is_off_hours(ts):
            continue

        principal_id = event.principal or ""
        # Dedup key: same principal + event_type + same UTC hour
        dedup_key = (principal_id, event.event_type, ts.date(), ts.hour)
        if dedup_key in _seen_off_hours:
            continue
        _seen_off_hours.add(dedup_key)

        entity_id = principal_id or event.resource_id or event.event_id
        signals.append(RiskSignal(
            signal_id=_sid(),
            entity_id=entity_id,
            signal_type="off_hours_assume_role",
            score=SIGNAL_WEIGHTS["off_hours_assume_role"],
            evidence=(
                f"Principal '{principal_id}' performed '{event.event_type}' at "
                f"{ts.strftime('%H:%M')} UTC (off-hours 20:00-06:00) "
                f"from {event.source_ip or 'unknown IP'}"
            ),
            timestamp=ts,
            principal_id=principal_id,
            namespace=event.namespace or "",
            source_ip=event.source_ip or "",
            correlation_id=event.correlation_id or "",
        ))

    return signals
