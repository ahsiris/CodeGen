from __future__ import annotations
 
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
 
if TYPE_CHECKING:
    from pipeline.ingestion import AssetRecord, IdentityRecord, IngestionPipeline
 
logger = logging.getLogger(__name__)
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Output types
# ─────────────────────────────────────────────────────────────────────────────
 
LABEL_EPHEMERAL        = "Ephemeral"
LABEL_LIKELY_EPHEMERAL = "Likely Ephemeral"
LABEL_PERSISTENT       = "Persistent"
 
 
@dataclass
class ClassificationResult:
    entity_id:   str
    entity_type: str
    label:       str
    confidence:  float
    score:       float
    reasons:     list[str]
    signals:     dict[str, Any]
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Tunable config
# ─────────────────────────────────────────────────────────────────────────────
 
@dataclass
class ClassifierConfig:
    # TTL thresholds
    ttl_ephemeral_secs:      float = 600.0    # < 10 min → strong ephemeral
    ttl_short_lived_secs:    float = 3600.0   # < 1 hr  → moderate ephemeral
    ttl_persistent_secs:     float = 86400.0  # > 24 hr → strong persistent
    ttl_attack_ephemeral_secs: float = 1800.0 # < 30 min on normally-persistent type = attack pattern
 
    # Label thresholds — lowered to capture all TTL<60min resources as ephemeral
    threshold_ephemeral:     float = 0.55
    threshold_likely:        float = 0.05
 
    # Asset weights (positive = toward Ephemeral)
    w_ttl_very_short:        float = 0.40
    w_ttl_short:             float = 0.25
    w_ttl_deleted:           float = 0.15
    w_known_ephemeral_type:  float = 0.20
    w_controller_owned:      float = 0.10
    w_no_tags:               float = 0.15
    w_burst_activity:        float = 0.10
    w_novel_principal:       float = 0.12
    w_off_hours:             float = 0.08
    w_public_exposure:       float = 0.10
    w_short_lived_identity:  float = 0.10
    w_no_controller:         float = 0.08
    w_privileged:            float = 0.12
    w_high_privilege_action: float = 0.15   # privilege_level=high on the action itself
    # Attack-pattern bonus when persistent-type resource is short-lived
    w_persistent_type_ephemeral_override: float = 0.30
 
    # Persistent counter-signals
    w_long_ttl:              float = -0.40
    w_full_tags:             float = -0.12
    w_not_deleted:           float = -0.08
    w_persistent_type:       float = -0.18
 
    # Identity weights
    wi_short_session:        float = 0.35
    wi_assumed_role:         float = 0.25
    wi_novel:                float = 0.20
    wi_off_hours:            float = 0.10
    wi_external_idp:         float = 0.10
    wi_high_privilege:       float = 0.08
    wi_cross_namespace:      float = 0.08
    wi_ip_diversity:         float = 0.06
    wi_long_session:         float = -0.30
    wi_known_principal:      float = -0.20
    wi_mfa:                  float = -0.05
 
 
# Resource types normally persistent (Deployment, Service, ConfigMap, etc.)
PERSISTENT_RESOURCE_TYPES: set[str] = {
    "Deployment", "StatefulSet", "DaemonSet", "Service",
    "ConfigMap", "Secret", "PersistentVolume", "IAMRole",
    "IAMPolicy", "S3Bucket", "VPC", "SecurityGroup",
    "s3_bucket", "security_group", "volume",
}
 
# Subset: persistent-type resources that attackers commonly create short-lived
# (buckets for exfil, SGs for backdoor, volumes for crypto mining)
# When seen with very short TTL, override the persistent-type penalty.
ATTACKER_SHORT_LIVED_TYPES: set[str] = {
    "s3_bucket", "security_group", "volume",
    "S3Bucket", "SecurityGroup",
}
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Score → label
# ─────────────────────────────────────────────────────────────────────────────
 
def _score_to_label_confidence(score: float, cfg: ClassifierConfig) -> tuple[str, float]:
    clamped    = max(-1.0, min(1.0, score))
    confidence = round((clamped + 1.0) / 2.0, 3)
    if score >= cfg.threshold_ephemeral:
        return LABEL_EPHEMERAL, confidence
    if score >= cfg.threshold_likely:
        return LABEL_LIKELY_EPHEMERAL, confidence
    return LABEL_PERSISTENT, round(1.0 - confidence, 3)
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Asset classification
# ─────────────────────────────────────────────────────────────────────────────
 
def _classify_asset(rec: "AssetRecord", cfg: ClassifierConfig) -> ClassificationResult:
    score:   float = 0.0
    reasons: list[tuple[float, str]] = []
    ttl    = rec.ttl_seconds
    is_del = rec.is_deleted
    rtype  = rec.resource_type
 
    def sig(name: str, default: Any = False) -> Any:
        return getattr(rec, name, default)
 
    signals: dict[str, Any] = {
        "resource_type":       rtype,
        "ttl_seconds":         ttl,
        "is_deleted":          is_del,
        "privileged":          rec.privileged,
        "controller":          rec.controller,
        "tag_completeness":    sig("tag_completeness", 0.0),
        "public_exposure":     sig("public_exposure", False),
        "privilege_level":     sig("privilege_level", "none"),
        "controller_owned":    sig("controller_owned", False),
        "known_ephemeral_type":sig("known_ephemeral_type", False),
        "short_lived_identity":sig("short_lived_identity", False),
        "off_hours":           sig("off_hours", False),
        "novel_principal":     sig("novel_principal", False),
        "burst_activity":      sig("burst_activity", False),
        "burst_groups":        sig("burst_groups", []),
    }
 
    # ── TTL rules ──────────────────────────────────────────────────────────────
    if ttl is not None:
        if ttl < cfg.ttl_ephemeral_secs:
            score += cfg.w_ttl_very_short
            reasons.append((cfg.w_ttl_very_short,
                f"TTL {ttl:.0f}s is very short (< {cfg.ttl_ephemeral_secs:.0f}s)"))
        elif ttl < cfg.ttl_short_lived_secs:
            score += cfg.w_ttl_short
            reasons.append((cfg.w_ttl_short,
                f"TTL {ttl:.0f}s is short (< {cfg.ttl_short_lived_secs:.0f}s)"))
        elif ttl >= cfg.ttl_persistent_secs:
            score += cfg.w_long_ttl
            reasons.append((cfg.w_long_ttl,
                f"TTL {ttl/3600:.1f}h indicates long-running resource"))
 
    # ── Deletion ───────────────────────────────────────────────────────────────
    if is_del:
        score += cfg.w_ttl_deleted
        reasons.append((cfg.w_ttl_deleted, "Resource has been deleted"))
    else:
        score += cfg.w_not_deleted
        reasons.append((cfg.w_not_deleted, "Resource is still active"))
 
    # ── Resource type ──────────────────────────────────────────────────────────
    if sig("known_ephemeral_type"):
        score += cfg.w_known_ephemeral_type
        reasons.append((cfg.w_known_ephemeral_type,
            f"Resource type '{rtype}' is inherently ephemeral"))
 
    if rtype in PERSISTENT_RESOURCE_TYPES:
        # KEY FIX: if this is normally-persistent but short-lived,
        # treat it as an attack/anomaly pattern instead of just persistent.
        is_attack_pattern = (
            rtype in ATTACKER_SHORT_LIVED_TYPES
            and ttl is not None
            and ttl < cfg.ttl_attack_ephemeral_secs
        )
        if is_attack_pattern:
            # Override: positive signal — this type is supposed to live for days,
            # but it lived under 30 min → strong ephemeral/anomaly indicator.
            score += cfg.w_persistent_type_ephemeral_override
            reasons.append((cfg.w_persistent_type_ephemeral_override,
                f"Resource type '{rtype}' is normally persistent but TTL {ttl:.0f}s "
                f"(< {cfg.ttl_attack_ephemeral_secs:.0f}s) — anomalous short-lived persistent resource"))
        else:
            score += cfg.w_persistent_type
            reasons.append((cfg.w_persistent_type,
                f"Resource type '{rtype}' is typically long-lived"))
 
    # ── Controller ownership ──────────────────────────────────────────────────
    if sig("controller_owned"):
        score += cfg.w_controller_owned
        reasons.append((cfg.w_controller_owned,
            f"Managed by controller '{rec.controller}' — lifecycle is automated"))
    elif ttl is not None and ttl < cfg.ttl_short_lived_secs:
        score += cfg.w_no_controller
        reasons.append((cfg.w_no_controller,
            "Short-lived resource has no controller (manual creation)"))
 
    # ── Tags ───────────────────────────────────────────────────────────────────
    tc = sig("tag_completeness", 0.0)
    if tc == 0.0:
        score += cfg.w_no_tags
        reasons.append((cfg.w_no_tags, "No expected tags — resource is unmanaged or ad-hoc"))
    elif tc == 1.0:
        score += cfg.w_full_tags
        reasons.append((cfg.w_full_tags, "All expected tags present — likely managed resource"))
 
    # ── Burst activity ─────────────────────────────────────────────────────────
    if sig("burst_activity"):
        score += cfg.w_burst_activity
        burst_keys = sig("burst_groups", [])
        reasons.append((cfg.w_burst_activity,
            f"Part of burst creation event ({', '.join(burst_keys[:2])})"))
 
    # ── Novel principal ────────────────────────────────────────────────────────
    if sig("novel_principal"):
        score += cfg.w_novel_principal
        reasons.append((cfg.w_novel_principal,
            "Created/accessed by a principal not seen in baseline"))
 
    # ── Off-hours ──────────────────────────────────────────────────────────────
    if sig("off_hours"):
        score += cfg.w_off_hours
        reasons.append((cfg.w_off_hours,
            "Activity detected outside business hours (08:00–18:00 UTC)"))
 
    # ── Public exposure ────────────────────────────────────────────────────────
    if sig("public_exposure"):
        score += cfg.w_public_exposure
        reasons.append((cfg.w_public_exposure,
            f"Resource has public IP {rec.public_ip} — elevated risk if ephemeral"))
 
    # ── Short-lived identity ───────────────────────────────────────────────────
    if sig("short_lived_identity"):
        score += cfg.w_short_lived_identity
        reasons.append((cfg.w_short_lived_identity,
            "Actor used short-lived credentials (assumed-role or ephemeral token)"))
 
    # ── Privileged context ────────────────────────────────────────────────────
    if rec.privileged and is_del:
        score += cfg.w_privileged
        reasons.append((cfg.w_privileged,
            "Privileged resource was short-lived — potential container escape or cleanup"))
 
    # ── High-privilege action (from audit privilege_level field) ──────────────
    # Strong attacker signal: high-privilege action on ephemeral resource
    priv_lvl = sig("privilege_level", "none")
    if priv_lvl == "high" and ttl is not None and ttl < cfg.ttl_short_lived_secs:
        score += cfg.w_high_privilege_action
        reasons.append((cfg.w_high_privilege_action,
            f"High-privilege action on short-lived resource (TTL {ttl:.0f}s) — attacker pattern"))
 
    reasons.sort(key=lambda x: abs(x[0]), reverse=True)
    label, confidence = _score_to_label_confidence(score, cfg)
 
    # ── TTL ground-truth floor ────────────────────────────────────────────────
    # If observed TTL clearly indicates ephemerality (< 60 min), the resource
    # IS ephemeral by definition — short-lived persistent types can still be
    # used briefly. Promote to at minimum "Likely Ephemeral" so the inventory
    # tracker captures it before disappearance (NIST CM-8).
    if ttl is not None and ttl < cfg.ttl_short_lived_secs and label == LABEL_PERSISTENT:
        label      = LABEL_LIKELY_EPHEMERAL
        confidence = max(confidence, 0.55)
 
    return ClassificationResult(
        entity_id   = rec.resource_id,
        entity_type = "asset",
        label       = label,
        confidence  = confidence,
        score       = round(score, 4),
        reasons     = [r for _, r in reasons],
        signals     = signals,
    )
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Identity classification (unchanged)
# ─────────────────────────────────────────────────────────────────────────────
 
def _classify_identity(rec: "IdentityRecord", cfg: ClassifierConfig) -> ClassificationResult:
    score:   float = 0.0
    reasons: list[tuple[float, str]] = []
 
    def sig(name: str, default: Any = False) -> Any:
        return getattr(rec, name, default)
 
    signals: dict[str, Any] = {
        "principal_type":    rec.principal_type,
        "session_ttl":       rec.session_ttl_seconds,
        "is_ephemeral":      rec.is_ephemeral_identity,
        "mfa":               rec.mfa,
        "external_idp":      rec.external_idp,
        "ip_diversity":      sig("ip_diversity", 1),
        "high_privilege":    sig("high_privilege", False),
        "short_session":     sig("short_session", False),
        "cross_namespace":   sig("cross_namespace", False),
        "off_hours_access":  sig("off_hours_access", False),
        "novel":             getattr(rec, "_novel", False),
        "permissions":       list(rec.permissions)[:10],
    }
 
    ttl = rec.session_ttl_seconds
    if ttl is not None:
        if ttl <= 900:
            score += cfg.wi_short_session
            reasons.append((cfg.wi_short_session,
                f"Session TTL {ttl:.0f}s (≤ 15 min) — ephemeral credential"))
        elif ttl >= 3600:
            score += cfg.wi_long_session
            reasons.append((cfg.wi_long_session,
                f"Session TTL {ttl/3600:.1f}h — long-lived credential"))
 
    if rec.principal_type == "AssumedRole":
        score += cfg.wi_assumed_role
        reasons.append((cfg.wi_assumed_role,
            "AssumedRole principals have inherently short-lived credentials"))
 
    is_novel = getattr(rec, "_novel", False)
    if is_novel:
        score += cfg.wi_novel
        reasons.append((cfg.wi_novel,
            "Principal not seen in known-good baseline — potentially new or compromised"))
    else:
        score += cfg.wi_known_principal
        reasons.append((cfg.wi_known_principal, "Principal is in known-good baseline"))
 
    if sig("off_hours_access"):
        score += cfg.wi_off_hours
        reasons.append((cfg.wi_off_hours,
            "Session active outside business hours (08:00–18:00 UTC)"))
 
    if rec.external_idp:
        score += cfg.wi_external_idp
        reasons.append((cfg.wi_external_idp,
            "Identity from external/federated IdP — credential lifecycle is external"))
 
    if sig("high_privilege"):
        score += cfg.wi_high_privilege
        reasons.append((cfg.wi_high_privilege, "Holds wildcard or high-privilege permissions"))
 
    if sig("cross_namespace"):
        score += cfg.wi_cross_namespace
        reasons.append((cfg.wi_cross_namespace,
            f"Active across {len(rec.namespaces)} namespaces — broad lateral reach"))
 
    ip_div = sig("ip_diversity", 1)
    if ip_div > 1:
        extra = (ip_div - 1) * cfg.wi_ip_diversity
        score += extra
        reasons.append((extra,
            f"{ip_div} distinct source IPs — may indicate credential sharing or theft"))
 
    if rec.mfa:
        score += cfg.wi_mfa
        reasons.append((cfg.wi_mfa, "MFA verified — lower risk"))
 
    reasons.sort(key=lambda x: abs(x[0]), reverse=True)
    label, confidence = _score_to_label_confidence(score, cfg)
 
    return ClassificationResult(
        entity_id   = rec.principal,
        entity_type = "identity",
        label       = label,
        confidence  = confidence,
        score       = round(score, 4),
        reasons     = [r for _, r in reasons],
        signals     = signals,
    )
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Main classifier
# ─────────────────────────────────────────────────────────────────────────────
 
class EphemeralClassifier:
    """
    Classifies all assets and identities in an ingested pipeline.
 
    Usage
    -----
        clf     = EphemeralClassifier()
        results = clf.classify_all(pipeline)
 
        risky = [r for r in results.values()
                 if r.entity_type == "asset" and r.label == "Ephemeral"]
    """
 
    def __init__(self, config: ClassifierConfig | None = None):
        self.config = config or ClassifierConfig()
 
    def classify_asset(self, rec: "AssetRecord") -> ClassificationResult:
        return _classify_asset(rec, self.config)
 
    def classify_identity(self, rec: "IdentityRecord") -> ClassificationResult:
        return _classify_identity(rec, self.config)
 
    def classify_all(self, pipeline: "IngestionPipeline") -> dict[str, ClassificationResult]:
        results: dict[str, ClassificationResult] = {}
        for rid, rec in pipeline.asset_registry.items():
            results[rid] = _classify_asset(rec, self.config)
        for principal, rec in pipeline.identity_registry.items():
            results[principal] = _classify_identity(rec, self.config)
        logger.info("Classification complete: %d entities (%d assets, %d identities)",
                    len(results), len(pipeline.asset_registry), len(pipeline.identity_registry))
        return results
 
    def summary_stats(self, results: dict[str, ClassificationResult]) -> dict:
        asset_results = [r for r in results.values() if r.entity_type == "asset"]
        id_results    = [r for r in results.values() if r.entity_type == "identity"]
        def label_counts(rs):
            counts = {LABEL_EPHEMERAL: 0, LABEL_LIKELY_EPHEMERAL: 0, LABEL_PERSISTENT: 0}
            for r in rs:
                counts[r.label] = counts.get(r.label, 0) + 1
            return counts
        return {
            "assets":     {"total": len(asset_results), "by_label": label_counts(asset_results)},
            "identities": {"total": len(id_results),    "by_label": label_counts(id_results)},
        }
 