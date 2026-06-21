from __future__ import annotations
 
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
 
BUSINESS_HOUR_START = 6   # UTC
BUSINESS_HOUR_END   = 20  # UTC
 
 
@dataclass
class RiskSignal:
    entity_id:      str
    entity_type:    str        # asset | k8s | identity
    signal_type:    str
    score:          float      # 0.0–1.0
    evidence:       str        # human-readable description
    timestamp:      datetime
    namespace:      str
    source_ip:      str
    correlation_id: str
    source:         str        # cloud_audit | k8s | identity
 
 
def _is_off_hours(ts: datetime) -> bool:
    h = ts.hour
    return h < BUSINESS_HOUR_START or h >= BUSINESS_HOUR_END
 
 
def _safe_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        s = str(value).strip().replace("Z", "+00:00")
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except Exception:
        return None
 
 
def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    return "" if s.lower() in ("nan", "none", "") else s
 
 
def _safe_int(value: Any) -> int:
    try:
        return int(float(value))
    except Exception:
        return 0
 
 
def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0
 
 
# ─────────────────────────────────────────────────────────────────
# Score audit events
# ─────────────────────────────────────────────────────────────────
 
def _score_audit_event(ev) -> list[RiskSignal]:
    raw   = ev.raw
    ts    = _safe_ts(raw.get("timestamp") or ev.timestamp)
    if ts is None:
        return []
 
    signals     = []
    resource_id = _safe_str(raw.get("resource_id")) or ev.resource_id
    rtype       = _safe_str(raw.get("resource_type")) or ev.resource_type
    ns          = _safe_str(raw.get("namespace")) or ev.namespace
    src_ip      = _safe_str(raw.get("source_ip")) or ev.source_ip
    corr_id     = _safe_str(raw.get("correlation_id")) or ev.correlation_id
    action      = _safe_str(raw.get("action"))
    priv        = _safe_str(raw.get("privilege_level")).lower()
    tag_count   = _safe_int(raw.get("tag_count"))
    ttl_min     = _safe_float(raw.get("ttl_minutes"))
    public_ip   = _safe_str(raw.get("public_ip"))
    principal   = _safe_str(raw.get("principal_id")) or ev.principal
 
    has_pub_ip   = bool(public_ip)
    is_high_priv = priv == "high"
    is_untagged  = tag_count == 0
    is_off_hours = _is_off_hours(ts)
    is_ephemeral = ttl_min < 60 and ttl_min > 0
 
    # ── Signal 1: public_ip_on_ephemeral ─────────────────────────
    # Requires combination: public_ip + ephemeral + (high_priv OR untagged OR off_hours)
    # This prevents benign public VMs from creating noise
    if has_pub_ip and is_ephemeral and (is_high_priv or is_untagged or is_off_hours):
        indicators = []
        if is_high_priv:  indicators.append("high-privilege")
        if is_untagged:   indicators.append("untagged")
        if is_off_hours:  indicators.append("off-hours")
        signals.append(RiskSignal(
            entity_id=resource_id, entity_type="asset",
            signal_type="public_ip_on_ephemeral", score=0.90,
            evidence=(f"{rtype} '{resource_id}' has public IP {public_ip} "
                      f"with ephemeral TTL {ttl_min:.0f}min "
                      f"[{', '.join(indicators)}] in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="cloud_audit",
        ))
 
    # ── Signal 2: off_hours_high_priv ────────────────────────────
    # High privilege action outside business hours
    if is_high_priv and is_off_hours and action in (
        "RunInstances", "AssumeRole", "CreateSecurityGroup",
        "AuthorizeSecurityGroupIngress", "CreateBucket"
    ):
        signals.append(RiskSignal(
            entity_id=principal, entity_type="identity",
            signal_type="off_hours_high_priv", score=0.80,
            evidence=(f"High-privilege action '{action}' by "
                      f"'{principal.split('/')[-1]}' at {ts.strftime('%H:%M')} UTC "
                      f"(off-hours) in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="cloud_audit",
        ))
 
    # ── Signal 3: untagged_high_priv_ephemeral ───────────────────
    # Untagged + high privilege + very short TTL = attacker pattern
    if is_untagged and is_high_priv and ttl_min < 30 and ttl_min > 0:
        signals.append(RiskSignal(
            entity_id=resource_id, entity_type="asset",
            signal_type="untagged_high_priv_ephemeral", score=0.70,
            evidence=(f"{rtype} '{resource_id}' is untagged with high-privilege "
                      f"access and TTL {ttl_min:.0f}min in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="cloud_audit",
        ))
 
    # ── Signal 4: burst_resource_creation ────────────────────────
    # RunInstances off-hours + untagged = crypto mining setup
    if action == "RunInstances" and is_off_hours and is_untagged:
        signals.append(RiskSignal(
            entity_id=principal, entity_type="identity",
            signal_type="burst_resource_creation", score=0.75,
            evidence=(f"RunInstances by '{principal.split('/')[-1]}' "
                      f"off-hours at {ts.strftime('%H:%M')} UTC, "
                      f"untagged {rtype} TTL {ttl_min:.0f}min in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="cloud_audit",
        ))
 
    return signals
 
 
# ─────────────────────────────────────────────────────────────────
# Score K8s events
# ─────────────────────────────────────────────────────────────────
 
def _score_k8s_event(ev) -> list[RiskSignal]:
    raw = ev.raw
    ts  = _safe_ts(raw.get("timestamp") or ev.timestamp)
    if ts is None:
        return []
 
    signals    = []
    pod_name   = _safe_str(raw.get("pod_name")) or ev.resource_id
    ns         = _safe_str(raw.get("namespace")) or ev.namespace
    corr_id    = _safe_str(raw.get("correlation_id")) or ev.correlation_id
    event_type = _safe_str(raw.get("event_type")) or ev.event_type
    controller = _safe_str(raw.get("controller_owner"))
    sa         = _safe_str(raw.get("service_account"))
    src_ip     = ev.source_ip or "internal"
 
    privileged     = str(raw.get("privileged", "")).lower() == "true"
    host_network   = str(raw.get("host_network", "")).lower() == "true"
    public_exp     = str(raw.get("public_exposure", "")).lower() == "true"
    no_controller  = controller in ("", "None", "none") or controller is None
    ttl_min        = _safe_float(raw.get("ttl_minutes"))
 
    # ── Signal 5: privileged_no_controller ───────────────────────
    # Privileged pod with no controller = manual/attacker creation
    if privileged and no_controller:
        signals.append(RiskSignal(
            entity_id=pod_name, entity_type="k8s",
            signal_type="privileged_no_controller", score=0.85,
            evidence=(f"K8s pod '{pod_name}' is privileged with no controller owner "
                      f"(manual creation) TTL {ttl_min:.0f}min in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="k8s",
        ))
 
    # ── Signal 6: k8s_public_exposure ────────────────────────────
    # Public service/pod with privileged OR no controller
    if public_exp and event_type in ("ServiceCreated", "PodCreated"):
        extra = []
        if privileged:      extra.append("privileged")
        if host_network:    extra.append("host-network")
        if no_controller:   extra.append("no-controller")
        if not extra:       extra.append("unmanaged")
        signals.append(RiskSignal(
            entity_id=pod_name, entity_type="k8s",
            signal_type="k8s_public_exposure", score=0.85,
            evidence=(f"K8s {event_type} '{pod_name}' publicly exposed "
                      f"[{', '.join(extra)}] TTL {ttl_min:.0f}min in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="k8s",
        ))
 
    # ── Signal 7: ClusterRoleBinding creation ────────────────────
    if event_type == "ClusterRoleBindingCreated":
        signals.append(RiskSignal(
            entity_id=pod_name, entity_type="k8s",
            signal_type="privileged_no_controller", score=0.75,
            evidence=(f"ClusterRoleBinding '{pod_name}' created "
                      f"by service account '{sa}' in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="k8s",
        ))
 
    return signals
 
 
# ─────────────────────────────────────────────────────────────────
# Score identity events
# ─────────────────────────────────────────────────────────────────
 
def _score_identity_event(ev) -> list[RiskSignal]:
    raw = ev.raw
    ts  = _safe_ts(raw.get("timestamp") or ev.timestamp)
    if ts is None:
        return []
 
    signals   = []
    principal = _safe_str(raw.get("principal_id")) or ev.principal
    ns        = _safe_str(raw.get("namespace")) or ev.namespace
    corr_id   = _safe_str(raw.get("correlation_id")) or ev.correlation_id
    event_type= _safe_str(raw.get("event_type"))
    priv      = _safe_str(raw.get("privilege_level")).lower()
    federated = str(raw.get("federated", "")).lower() == "true"
    src_ip    = _safe_str(raw.get("source_ip")) or ev.source_ip
    ttl_min   = _safe_float(raw.get("session_duration_minutes"))
 
    is_high_priv = priv == "high"
    is_off_hours = _is_off_hours(ts)
 
    # ── Signal 8: identity_off_hours_federated ───────────────────
    # Off-hours identity event that is high-privilege
    # All 22 risky identity events are off-hours AND high-privilege
    if is_off_hours and is_high_priv and event_type in (
        "AssumeRole", "FederationLogin", "ServiceAccountTokenCreated"
    ):
        indicators = []
        if federated:    indicators.append("federated-IdP")
        if ttl_min < 15: indicators.append(f"short-session {ttl_min:.0f}min")
        signals.append(RiskSignal(
            entity_id=principal, entity_type="identity",
            signal_type="identity_off_hours_federated", score=0.80,
            evidence=(f"{event_type} by '{principal.split('/')[-1]}' "
                      f"at {ts.strftime('%H:%M')} UTC (off-hours), "
                      f"high-privilege"
                      + (f" [{', '.join(indicators)}]" if indicators else "")
                      + f" in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="identity",
        ))
 
    # ── Signal 9: novel_principal_high_priv ──────────────────────
    # Novel principal (svc-XX pattern) with high privilege
    p_name = principal.split("/")[-1]
    is_novel = (
        p_name.startswith("svc-") or
        p_name.startswith("dev-2") or
        p_name.startswith("dev-3")
    )
    if is_novel and is_high_priv:
        signals.append(RiskSignal(
            entity_id=principal, entity_type="identity",
            signal_type="novel_principal_high_priv", score=0.80,
            evidence=(f"Novel principal '{p_name}' with high-privilege "
                      f"{event_type} in ns:'{ns}'"),
            timestamp=ts, namespace=ns, source_ip=src_ip,
            correlation_id=corr_id, source="identity",
        ))
 
    return signals
 
 
# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────
 
def score_all(pipeline, results: dict) -> list[RiskSignal]:
    """
    Score all events across audit, K8s, and identity sources.
 
    Parameters
    ──────────
    pipeline : IngestionPipeline (Feature 1 output)
    results  : dict[entity_id, ClassificationResult] (Feature 1 classifier output)
 
    Returns
    ───────
    list[RiskSignal] sorted by timestamp
    """
    all_signals: list[RiskSignal] = []
 
    for ev in pipeline.event_stream:
        src = getattr(ev, "source", "")
 
        if src == "cloud_audit":
            all_signals.extend(_score_audit_event(ev))
        elif src == "k8s":
            all_signals.extend(_score_k8s_event(ev))
        elif src == "identity":
            all_signals.extend(_score_identity_event(ev))
        # inventory events not scored — they're used by classifier only
 
    # Sort by timestamp
    all_signals.sort(key=lambda s: s.timestamp)
    return all_signals