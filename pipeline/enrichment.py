from __future__ import annotations
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from pipeline.ingestion import AssetRecord, IdentityRecord, IngestionPipeline, UnifiedEvent
 
logger = logging.getLogger(__name__)
 
BUSINESS_HOUR_START = 8
BUSINESS_HOUR_END   = 18
EXPECTED_TAGS: set[str] = {"app", "team", "env"}
 
EPHEMERAL_RESOURCE_TYPES: set[str] = {
    "Pod", "Job", "CronJob", "Session", "spot_instance", "BatchJob", "TaskDefinition", "ECSTask",
}
CONTROLLER_KINDS: set[str] = {
    "Job", "ReplicaSet", "StatefulSet", "DaemonSet", "Deployment",
    "CronJob", "HorizontalPodAutoscaler", "HPA", "SpotFleet", "AutoScalingGroup",
}
HIGH_PRIVILEGE_PATTERNS: set[str] = {"s3:*", "ec2:*", "iam:*", "sts:*", "*:*", "pods:*", "exec:*", "secrets:*"}
SENSITIVE_PERMS: set[str] = {"iam:CreateUser", "iam:AttachRolePolicy", "sts:AssumeRole", "ec2:RunInstances"}
 
BURST_WINDOW_SECONDS = 300
BURST_THRESHOLD      = 5
 
def _compute_burst_windows(events: list["UnifiedEvent"]) -> dict[str, set[str]]:
    groups: dict[tuple, list[datetime]] = defaultdict(list)
    event_resource_map: dict[tuple, list[str]] = defaultdict(list)
    for ev in events:
        key = (ev.event_type, ev.namespace)
        groups[key].append(ev.timestamp)
        event_resource_map[key].append(ev.resource_id)
    burst_resources: dict[str, set[str]] = defaultdict(set)
    for key, timestamps in groups.items():
        paired = sorted(zip(timestamps, event_resource_map[key]), key=lambda x: x[0])
        left = 0
        for right in range(len(paired)):
            while (paired[right][0] - paired[left][0]).total_seconds() > BURST_WINDOW_SECONDS:
                left += 1
            if right - left + 1 >= BURST_THRESHOLD:
                burst_key = f"{key[0]}@{key[1]}"
                for _, rid in paired[left:right + 1]:
                    burst_resources[rid].add(burst_key)
    return burst_resources
 
def _off_hours(ts: datetime | None) -> bool:
    if ts is None: return False
    h = ts.hour
    return h < BUSINESS_HOUR_START or h >= BUSINESS_HOUR_END
 
def _tag_completeness(tags: dict) -> float:
    if not EXPECTED_TAGS: return 1.0
    present = sum(1 for t in EXPECTED_TAGS if t in tags)
    return round(present / len(EXPECTED_TAGS), 3)
 
def _privilege_level(privileged: bool, host_network: bool = False, permissions: set[str] | None = None) -> str:
    if privileged and host_network: return "critical"
    if privileged: return "high"
    perms = permissions or set()
    if HIGH_PRIVILEGE_PATTERNS & perms: return "high"
    if SENSITIVE_PERMS & perms: return "medium"
    if perms: return "low"
    return "none"
 
def _controller_owned(controller: str | None) -> bool:
    if not controller or controller in ("None", "none", "nan", ""): return False
    kind = controller.split("/")[0] if "/" in controller else controller
    return kind in CONTROLLER_KINDS
 
def _known_ephemeral_type(resource_type: str) -> bool:
    return resource_type in EPHEMERAL_RESOURCE_TYPES
 
def _enrich_asset(rec: "AssetRecord", events: list["UnifiedEvent"],
                   burst_resources: dict[str, set[str]], identity_registry: dict[str, "IdentityRecord"]) -> None:
    actors = {ev.principal for ev in events if ev.principal not in ("system", "inventory-scanner", "")}
    rec.off_hours          = any(_off_hours(ev.timestamp) for ev in events)
    rec.novel_principal    = any(getattr(identity_registry.get(a), "_novel", False) for a in actors)
    rec.burst_activity     = rec.resource_id in burst_resources
    rec.burst_groups       = list(burst_resources.get(rec.resource_id, []))
    rec.tag_completeness   = _tag_completeness(rec.tags)
    inv_public             = getattr(rec, "_public_exposure_flag", False)
    rec.public_exposure    = (rec.public_ip is not None) or inv_public
    actor_perms: set[str] = set()
    for a in actors:
        ir = identity_registry.get(a)
        if ir: actor_perms.update(ir.permissions)
    host_network = any(
        ev.raw.get("host_network") is True or str(ev.raw.get("host_network", "")).lower() == "true"
        for ev in events
    )
    rec.privilege_level    = _privilege_level(privileged=rec.privileged, host_network=host_network, permissions=actor_perms)
 
    # If any audit event on this resource was at high privilege, mark high
    for ev in events:
        ev_priv = str(ev.raw.get("privilege_level", "")).lower().strip()
        if ev_priv == "high":
            rec.privilege_level = "high"
            break
        if ev_priv == "medium" and rec.privilege_level == "none":
            rec.privilege_level = "medium"
    rec.controller_owned   = _controller_owned(rec.controller)
    rec.known_ephemeral_type = _known_ephemeral_type(rec.resource_type)
    rec.short_lived_identity = any(
        identity_registry[a].is_ephemeral_identity for a in actors if a in identity_registry
    )
 
def _enrich_identity(rec: "IdentityRecord", events: list["UnifiedEvent"]) -> None:
    rec.off_hours_access = any(_off_hours(ev.timestamp) for ev in events)
    rec.ip_diversity     = len(rec.source_ips)
    rec.high_privilege   = bool(HIGH_PRIVILEGE_PATTERNS & rec.permissions)
    rec.short_session    = (rec.session_ttl_seconds is not None and rec.session_ttl_seconds <= 900)
    rec.cross_namespace  = len(rec.namespaces) > 1
 
def enrich(pipeline: "IngestionPipeline") -> None:
    events = pipeline.event_stream
    assets = pipeline.asset_registry
    ids    = pipeline.identity_registry
    burst_resources = _compute_burst_windows(events)
    events_by_resource:  dict[str, list["UnifiedEvent"]] = defaultdict(list)
    events_by_principal: dict[str, list["UnifiedEvent"]] = defaultdict(list)
    for ev in events:
        if ev.resource_id: events_by_resource[ev.resource_id].append(ev)
        if ev.principal and ev.principal not in ("system", "inventory-scanner"):
            events_by_principal[ev.principal].append(ev)
    for rid, rec in assets.items():
        _enrich_asset(rec, events_by_resource.get(rid, []), burst_resources, ids)
    for principal, rec in ids.items():
        _enrich_identity(rec, events_by_principal.get(principal, []))
 