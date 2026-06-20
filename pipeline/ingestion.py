from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Domain models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UnifiedEvent:
    """Single normalised event from any telemetry source."""
    event_id:       str
    timestamp:      datetime
    source:         str           # cloud_audit | k8s | identity | inventory
    event_type:     str
    resource_id:    str
    resource_type:  str
    principal:      str
    namespace:      str
    source_ip:      str
    tags:           dict[str, str]
    raw:            dict[str, Any]  # original row for traceability
    correlation_id: str = ""       # shared key linking events across sources


@dataclass
class AssetRecord:
    """Lifecycle record for one discovered resource."""
    resource_id:   str
    resource_type: str
    namespace:     str
    controller:    str | None      # e.g. "Job/ci-pipeline-job" or controller_owner
    tags:          dict[str, str]
    public_ip:     str | None
    privileged:    bool
    region:        str

    first_seen:    datetime | None = None
    last_seen:     datetime | None = None
    created_at:    datetime | None = None   # from inventory
    deleted_at:    datetime | None = None   # from inventory or DELETE event
    observed_events: int = 0
    explicit_ttl_seconds: float | None = None

    @property
    def ttl_seconds(self) -> float | None:
        """Observed lifetime in seconds (None if still alive)."""
        if self.explicit_ttl_seconds is not None:
            return self.explicit_ttl_seconds
        end = self.deleted_at or self.last_seen
        start = self.created_at or self.first_seen
        if end and start and end > start:
            return (end - start).total_seconds()
        return None

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    @property
    def lifecycle_class(self) -> str:
        ttl = self.ttl_seconds
        if ttl is None:
            return "active"
        if ttl < 600:          # < 10 min
            return "ephemeral"
        if ttl < 3600:         # < 1 hr
            return "short_lived"
        return "persistent"


@dataclass
class IdentityRecord:
    """Lifecycle record for one discovered principal."""
    principal:      str
    principal_type: str         # IAMUser | AssumedRole | ServiceAccount | OIDCFederated | LambdaExecutionRole
    namespace:      str

    first_seen:     datetime | None = None
    last_seen:      datetime | None = None
    session_ttl_seconds: float | None = None
    source_ips:     set[str] = field(default_factory=set)
    namespaces:     set[str] = field(default_factory=set)
    permissions:    set[str] = field(default_factory=set)
    privilege_level: str = "low"
    mfa:            bool = False
    external_idp:   bool = False
    event_count:    int  = 0
    session_ids:    list[str] = field(default_factory=list)

    @property
    def is_ephemeral_identity(self) -> bool:
        return (
            self.session_ttl_seconds is not None
            and self.session_ttl_seconds <= 900  # 15-min assumed-role threshold
        ) or self.principal_type == "AssumedRole"

    @property
    def is_novel(self) -> bool:
        """Marked externally by ingestion pipeline after baseline comparison."""
        return getattr(self, "_novel", False)


@dataclass
class InventorySnapshot:
    snapshot_time: datetime
    total:         int
    active:        list[AssetRecord]
    expired:       list[AssetRecord]   # deleted but within last 24 h
    ephemeral:     list[AssetRecord]   # TTL < 10 min
    persistent:    list[AssetRecord]   # alive > 1 hr


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

# Known-good principals baseline — uses the ARN patterns present in the dataset
_KNOWN_PRINCIPALS: set[str] = {
    "arn:aws:iam::123456789012:role/ci-runner-1",
    "arn:aws:iam::123456789012:role/ci-runner-2",
    "arn:aws:iam::123456789012:role/ci-runner-3",
    "arn:aws:iam::123456789012:role/ci-runner-4",
    "arn:aws:iam::123456789012:role/ci-runner-5",
    "arn:aws:iam::123456789012:role/ci-runner-6",
    "arn:aws:iam::123456789012:user/dev-1",
    "arn:aws:iam::123456789012:user/dev-2",
    "arn:aws:iam::123456789012:user/dev-3",
    "arn:aws:iam::123456789012:user/dev-4",
    "arn:aws:iam::123456789012:user/dev-5",
    "arn:aws:iam::123456789012:user/dev-6",
    "ci-runner",
    "analytics-sa",
    "admin-sa",
    "monitor-sa",
    "deploy-sa",
    "default",
}

# Verbs/event types that indicate resource deletion
DELETE_VERBS: set[str] = {
    "TerminateInstances",        # cloud audit: EC2 termination
    "DeleteBucket",              # cloud audit: S3 bucket deletion
    "PodDeleted",                # k8s: pod deletion
    "ResourceDeleted",           # synthetic event from inventory
    "DELETED",
}

# Map K8s event_type → inferred resource kind
_K8S_EVENT_TYPE_TO_RESOURCE_KIND: dict[str, str] = {
    "PodCreated":                  "Pod",
    "PodDeleted":                  "Pod",
    "DeploymentCreated":           "Deployment",
    "ServiceCreated":              "Service",
    "RoleBindingCreated":          "RoleBinding",
    "ClusterRoleBindingCreated":   "ClusterRoleBinding",
    "ConfigMapCreated":            "ConfigMap",
    "SecretMounted":               "Secret",
}


def _parse_ts(value: Any) -> datetime | None:
    if pd.isna(value) or value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    s = str(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    logger.warning("Could not parse timestamp: %r", value)
    return None


def _parse_tags(value: Any) -> dict[str, str]:
    if pd.isna(value) or value is None or value == "":
        return {}
    try:
        return json.loads(str(value))
    except (json.JSONDecodeError, TypeError):
        return {}


def _safe_str(value: Any, default: str = "") -> str:
    if pd.isna(value) or value is None:
        return default
    return str(value).strip()


def _safe_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if pd.isna(value) or value is None:
        return False
    return str(value).lower() in ("true", "1", "yes")


def _safe_float(value: Any) -> float | None:
    if pd.isna(value) or value is None or value == "":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _safe_int(value: Any) -> int:
    """Parse an integer, returning 0 on failure."""
    if pd.isna(value) or value is None or value == "":
        return 0
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Source-specific parsers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cloud_audit(df: pd.DataFrame) -> list[UnifiedEvent]:
    """
    Parse cloud_audit_logs.csv.
    
    Actual columns: event_id, timestamp, principal_id, principal_type, action,
    resource_id, resource_type, region, tags_present, tag_count, public_ip,
    privilege_level, namespace, ttl_minutes, source_ip, user_agent, correlation_id
    """
    events: list[UnifiedEvent] = []
    for i, row in df.iterrows():
        ts = _parse_ts(row.get("timestamp"))
        if ts is None:
            continue

        # Build pseudo-tags from tags_present / tag_count for tag_completeness
        tags: dict[str, str] = {}
        if _safe_bool(row.get("tags_present")):
            tag_count = _safe_int(row.get("tag_count"))
            # Synthesise tag keys so _tag_completeness can count them
            for t_idx in range(tag_count):
                # Use known expected tags first, then generic names
                known = ["app", "team", "env"]
                key = known[t_idx] if t_idx < len(known) else f"tag_{t_idx}"
                tags[key] = "present"

        events.append(UnifiedEvent(
            event_id       = _safe_str(row.get("event_id"), default=f"audit-{i}"),
            timestamp      = ts,
            source         = "cloud_audit",
            event_type     = _safe_str(row.get("action")),           # CSV column is "action"
            resource_id    = _safe_str(row.get("resource_id")),
            resource_type  = _safe_str(row.get("resource_type")),
            principal      = _safe_str(row.get("principal_id")),     # CSV column is "principal_id"
            namespace      = _safe_str(row.get("namespace")),
            source_ip      = _safe_str(row.get("source_ip")),
            tags           = tags,
            raw            = row.to_dict(),
            correlation_id = _safe_str(row.get("correlation_id")),
        ))
    return events


def _parse_k8s(df: pd.DataFrame) -> list[UnifiedEvent]:
    """
    Parse kubernetes_events.csv.
    
    Actual columns: event_id, timestamp, namespace, pod_name, event_type,
    controller_owner, service_account, image_name, privileged, host_network,
    public_exposure, node_port, ttl_minutes, labels_present, cpu_request,
    memory_request, correlation_id
    """
    events: list[UnifiedEvent] = []
    for i, row in df.iterrows():
        ts = _parse_ts(row.get("timestamp"))
        if ts is None:
            continue

        pod_name   = _safe_str(row.get("pod_name"))          # CSV column is "pod_name"
        event_type = _safe_str(row.get("event_type"))
        ns         = _safe_str(row.get("namespace"))

        # Infer resource kind from event_type
        resource_kind = _K8S_EVENT_TYPE_TO_RESOURCE_KIND.get(event_type, "Pod")
        # Resource ID = "<kind_lower>/<pod_name>" for registry lookup
        resource_id = f"{resource_kind.lower()}/{pod_name}" if pod_name else f"{resource_kind.lower()}/unknown-{i}"

        # Build pseudo-tags from labels_present boolean
        tags: dict[str, str] = {}
        if _safe_bool(row.get("labels_present")):
            tags = {"app": "present", "team": "present", "env": "present"}

        # Use service_account as the principal (represents who owns this workload)
        principal = _safe_str(row.get("service_account"), default="system")

        events.append(UnifiedEvent(
            event_id       = _safe_str(row.get("event_id"), default=f"k8s-{i}"),
            timestamp      = ts,
            source         = "k8s",
            event_type     = event_type,
            resource_id    = resource_id,
            resource_type  = resource_kind,
            principal      = principal,
            namespace      = ns,
            source_ip      = "internal",
            tags           = tags,
            raw            = row.to_dict(),
            correlation_id = _safe_str(row.get("correlation_id")),
        ))
    return events


def _parse_identity(df: pd.DataFrame) -> list[UnifiedEvent]:
    """
    Parse identity_sessions.csv.
    
    Actual columns: session_id, timestamp, principal_id, identity_type,
    event_type, role_name, session_duration_minutes, federated, source_ip,
    namespace, privilege_level, correlation_id
    """
    events: list[UnifiedEvent] = []
    for i, row in df.iterrows():
        ts = _parse_ts(row.get("timestamp"))
        if ts is None:
            continue
        principal = _safe_str(row.get("principal_id"))               # CSV column is "principal_id"
        events.append(UnifiedEvent(
            event_id       = f"identity-{i}",
            timestamp      = ts,
            source         = "identity",
            event_type     = _safe_str(row.get("event_type"), default="SessionCreated"),  # use actual event_type column
            resource_id    = _safe_str(row.get("session_id")),
            resource_type  = "Session",
            principal      = principal,
            namespace      = _safe_str(row.get("namespace")),
            source_ip      = _safe_str(row.get("source_ip")),
            tags           = {},
            raw            = row.to_dict(),
            correlation_id = _safe_str(row.get("correlation_id")),
        ))
    return events


def _parse_inventory(df: pd.DataFrame) -> list[UnifiedEvent]:
    """
    Parse resource_inventory.csv.
    
    Actual columns: resource_id, resource_type, created_time, deleted_time,
    ttl_minutes, namespace, owner, public_exposure, privilege_level, ephemeral_label
    """
    events: list[UnifiedEvent] = []
    for i, row in df.iterrows():
        # Emit a synthetic "Discovered" event at created_time
        ts = _parse_ts(row.get("created_time"))                     # CSV column is "created_time"
        if ts is None:
            continue
        events.append(UnifiedEvent(
            event_id       = f"inv-{i}",
            timestamp      = ts,
            source         = "inventory",
            event_type     = "ResourceDiscovered",
            resource_id    = _safe_str(row.get("resource_id")),
            resource_type  = _safe_str(row.get("resource_type")),
            principal      = _safe_str(row.get("owner"), default="inventory-scanner"),  # use "owner" column
            namespace      = _safe_str(row.get("namespace")),
            source_ip      = "",
            tags           = {},                                     # inventory CSV has no tags column
            raw            = row.to_dict(),
            correlation_id = "",                                     # inventory has no correlation_id
        ))
        # Also emit deletion event if present
        del_ts = _parse_ts(row.get("deleted_time"))                 # CSV column is "deleted_time"
        if del_ts:
            events.append(UnifiedEvent(
                event_id       = f"inv-del-{i}",
                timestamp      = del_ts,
                source         = "inventory",
                event_type     = "ResourceDeleted",
                resource_id    = _safe_str(row.get("resource_id")),
                resource_type  = _safe_str(row.get("resource_type")),
                principal      = _safe_str(row.get("owner"), default="inventory-scanner"),
                namespace      = _safe_str(row.get("namespace")),
                source_ip      = "",
                tags           = {},
                raw            = row.to_dict(),
                correlation_id = "",
            ))
    return events


# ─────────────────────────────────────────────────────────────────────────────
# Registry builders
# ─────────────────────────────────────────────────────────────────────────────

def _build_asset_registry(
    events: list[UnifiedEvent],
    inventory_df: pd.DataFrame,
) -> dict[str, AssetRecord]:
    """
    Merge event stream observations with structured inventory metadata.
    Inventory is authoritative for created_time / deleted_time / lifecycle.
    Events fill in first_seen / last_seen and catch resources not in inventory.
    """
    registry: dict[str, AssetRecord] = {}

    # Seed from inventory (most reliable lifecycle source)
    for _, row in inventory_df.iterrows():
        rid = _safe_str(row.get("resource_id"))
        if not rid:
            continue
        registry[rid] = AssetRecord(
            resource_id   = rid,
            resource_type = _safe_str(row.get("resource_type")),
            namespace     = _safe_str(row.get("namespace")),
            controller    = None,                                    # inventory has no controller column
            tags          = {},                                      # inventory has no tags column
            public_ip     = None,                                    # inventory has public_exposure (bool), not IP
            privileged    = False,                                   # inventory has no privileged column
            region        = "",                                      # inventory has no region column
            created_at    = _parse_ts(row.get("created_time")),      # CSV column is "created_time"
            deleted_at    = _parse_ts(row.get("deleted_time")),      # CSV column is "deleted_time"
        )
        # Store public_exposure as a bool attribute for enrichment
        rec = registry[rid]
        rec._public_exposure_flag = _safe_bool(row.get("public_exposure"))  # type: ignore[attr-defined]
        rec._privilege_level = _safe_str(row.get("privilege_level"))        # type: ignore[attr-defined]
        rec._ephemeral_label = _safe_str(row.get("ephemeral_label"))        # type: ignore[attr-defined]
        rec._owner = _safe_str(row.get("owner"))                            # type: ignore[attr-defined]
        ttl_m = _safe_float(row.get("ttl_minutes"))
        if ttl_m is not None:
            rec.explicit_ttl_seconds = ttl_m * 60.0

    # Walk event stream to update first/last seen and catch unlisted resources
    for ev in events:
        rid = ev.resource_id
        if not rid or ev.resource_type in ("Session", ""):
            continue

        if rid not in registry:
            # Resource only seen in event stream — create minimal record
            registry[rid] = AssetRecord(
                resource_id   = rid,
                resource_type = ev.resource_type,
                namespace     = ev.namespace,
                controller    = None,
                tags          = ev.tags,
                public_ip     = _safe_str(ev.raw.get("public_ip")) or None,
                privileged    = _safe_bool(ev.raw.get("privileged")),
                region        = _safe_str(ev.raw.get("region")),
            )

        rec = registry[rid]

        # first_seen / last_seen from events
        if rec.first_seen is None or ev.timestamp < rec.first_seen:
            rec.first_seen = ev.timestamp
        if rec.last_seen is None or ev.timestamp > rec.last_seen:
            rec.last_seen = ev.timestamp

        rec.observed_events += 1

        # If inventory didn't capture deletion but an event implies it
        if ev.event_type in DELETE_VERBS and rec.deleted_at is None:
            rec.deleted_at = ev.timestamp

        # Enrich tags if event had more
        if ev.tags:
            rec.tags = {**ev.tags, **rec.tags}  # inventory tags win on conflict

        # Carry forward controller_owner from K8s events
        controller_owner = ev.raw.get("controller_owner")
        if controller_owner and not pd.isna(controller_owner) and rec.controller is None:
            rec.controller = str(controller_owner)

        # Carry forward privileged flag from K8s events
        if _safe_bool(ev.raw.get("privileged")):
            rec.privileged = True

        # Carry forward public_ip from cloud audit events
        pip = _safe_str(ev.raw.get("public_ip"))
        if pip and rec.public_ip is None:
            rec.public_ip = pip

        # Carry forward region from cloud audit events
        region = _safe_str(ev.raw.get("region"))
        if region and not rec.region:
            rec.region = region

        ttl_m = _safe_float(ev.raw.get("ttl_minutes"))
        if ttl_m is not None:
            if rec.explicit_ttl_seconds is None:
                rec.explicit_ttl_seconds = ttl_m * 60.0
            else:
                rec.explicit_ttl_seconds = min(rec.explicit_ttl_seconds, ttl_m * 60.0)

    return registry


def _build_identity_registry(
    events: list[UnifiedEvent],
    identity_df: pd.DataFrame,
) -> dict[str, IdentityRecord]:
    """
    Build identity registry. Identity session CSV is authoritative for
    identity_type and session TTL. Events add IP diversity and event counts.
    """
    registry: dict[str, IdentityRecord] = {}

    # Seed from identity sessions CSV
    for _, row in identity_df.iterrows():
        principal = _safe_str(row.get("principal_id"))               # CSV column is "principal_id"
        if not principal:
            continue
        if principal not in registry:
            registry[principal] = IdentityRecord(
                principal      = principal,
                principal_type = _safe_str(row.get("identity_type"), "Unknown"),  # CSV column is "identity_type"
                namespace      = _safe_str(row.get("namespace")),
            )
        rec = registry[principal]
        ts  = _parse_ts(row.get("timestamp"))

        if ts:
            if rec.first_seen is None or ts < rec.first_seen:
                rec.first_seen = ts
            if rec.last_seen is None or ts > rec.last_seen:
                rec.last_seen = ts

        # Session TTL — CSV has "session_duration_minutes", convert to seconds
        ttl_minutes = _safe_float(row.get("session_duration_minutes"))
        if ttl_minutes is not None:
            ttl_seconds = ttl_minutes * 60.0  # convert minutes → seconds
            if rec.session_ttl_seconds is None or ttl_seconds < rec.session_ttl_seconds:
                rec.session_ttl_seconds = ttl_seconds

        ip = _safe_str(row.get("source_ip"))
        if ip:
            rec.source_ips.add(ip)

        ns = _safe_str(row.get("namespace"))
        if ns:
            rec.namespaces.add(ns)

        # Read privilege_level from the CSV row (no "permissions" column exists)
        priv = _safe_str(row.get("privilege_level"))
        if priv and priv in ("high", "critical"):
            rec.privilege_level = priv
            # Also add a synthetic high-privilege marker for enrichment compatibility
            rec.permissions.add("sts:*")

        # Read federated flag instead of non-existent "external_idp"
        if _safe_bool(row.get("federated")):
            rec.external_idp = True

        sid = _safe_str(row.get("session_id"))
        if sid and sid not in rec.session_ids:
            rec.session_ids.append(sid)

    # Walk event stream to count activity and catch principals not in session CSV
    for ev in events:
        p = ev.principal
        if not p or p in ("system", "inventory-scanner"):
            continue

        if p not in registry:
            registry[p] = IdentityRecord(
                principal      = p,
                principal_type = _infer_principal_type(p),
                namespace      = ev.namespace,
            )

        rec = registry[p]
        rec.event_count += 1
        if ev.source_ip and ev.source_ip != "internal":
            rec.source_ips.add(ev.source_ip)
        if ev.namespace:
            rec.namespaces.add(ev.namespace)

        if ev.timestamp:
            if rec.first_seen is None or ev.timestamp < rec.first_seen:
                rec.first_seen = ev.timestamp
            if rec.last_seen is None or ev.timestamp > rec.last_seen:
                rec.last_seen = ev.timestamp

        # Pick up privilege_level from cloud audit events
        priv = _safe_str(ev.raw.get("privilege_level"))
        if priv == "high":
            rec.privilege_level = "high"
            rec.permissions.add("sts:*")

    # Mark novel principals (not in known baseline)
    for principal, rec in registry.items():
        rec._novel = principal not in _KNOWN_PRINCIPALS  # type: ignore[attr-defined]

    return registry


def _infer_principal_type(principal: str) -> str:
    """Infer principal type from ARN or short-name format."""
    p = principal.lower()
    # AWS ARN patterns
    if "assumed-role/" in p:
        return "AssumedRole"
    if ":role/" in p:
        return "IAMUser"  # IAM roles accessed via principal_id show as role ARN
    if ":user/" in p:
        return "IAMUser"
    # K8s service account short names
    if p.startswith("sa/") or p.startswith("serviceaccount/"):
        return "ServiceAccount"
    if p in ("ci-runner", "analytics-sa", "admin-sa", "debug-sa",
             "monitor-sa", "deploy-sa", "default"):
        return "ServiceAccount"
    if p.startswith("system:"):
        return "SystemAccount"
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ─────────────────────────────────────────────────────────────────────────────

class IngestionPipeline:
    """
    Orchestrates multi-source ingestion.

    Usage
    -----
        pipeline = IngestionPipeline("data/")
        pipeline.ingest()

        pipeline.event_stream          # chronological list of UnifiedEvent
        pipeline.asset_registry        # dict[resource_id, AssetRecord]
        pipeline.identity_registry     # dict[principal, IdentityRecord]
        pipeline.inventory_snapshot()  # InventorySnapshot
    """

    def __init__(self, data_dir: str = "data/"):
        self.data_dir = Path(data_dir)
        self.event_stream:     list[UnifiedEvent]      = []
        self.asset_registry:   dict[str, AssetRecord]  = {}
        self.identity_registry: dict[str, IdentityRecord] = {}
        self._raw: dict[str, pd.DataFrame] = {}

    # ── Loaders ───────────────────────────────────────────────────────────────

    def _load_csv(self, filename: str) -> pd.DataFrame:
        path = self.data_dir / filename
        if not path.exists():
            logger.warning("File not found, skipping: %s", path)
            return pd.DataFrame()
        df = pd.read_csv(path)
        logger.info("Loaded %s: %d rows", filename, len(df))
        return df

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(self) -> "IngestionPipeline":
        """Run full ingestion. Idempotent — call again to refresh."""
        logger.info("=== Starting ingestion pipeline ===")

        # 1. Load raw CSVs
        audit_df = self._load_csv("cloud_audit_logs.csv")
        k8s_df   = self._load_csv("kubernetes_events.csv")
        id_df    = self._load_csv("identity_sessions.csv")
        inv_df   = self._load_csv("resource_inventory.csv")

        self._raw = {
            "cloud_audit":  audit_df,
            "k8s":          k8s_df,
            "identity":     id_df,
            "inventory":    inv_df,
        }

        # 2. Parse each source into UnifiedEvents
        all_events: list[UnifiedEvent] = []
        if not audit_df.empty:
            all_events.extend(_parse_cloud_audit(audit_df))
        if not k8s_df.empty:
            all_events.extend(_parse_k8s(k8s_df))
        if not id_df.empty:
            all_events.extend(_parse_identity(id_df))
        if not inv_df.empty:
            all_events.extend(_parse_inventory(inv_df))

        # 3. Sort chronologically — unified event stream
        self.event_stream = sorted(all_events, key=lambda e: e.timestamp)
        logger.info("Unified event stream: %d events", len(self.event_stream))

        # 4. Build registries
        self.asset_registry = _build_asset_registry(
            self.event_stream,
            inv_df if not inv_df.empty else pd.DataFrame(),
        )
        self.identity_registry = _build_identity_registry(
            self.event_stream,
            id_df if not id_df.empty else pd.DataFrame(),
        )

        logger.info(
            "Registries built: %d assets, %d identities",
            len(self.asset_registry),
            len(self.identity_registry),
        )
        return self

    def inventory_snapshot(self, reference_time: datetime | None = None) -> InventorySnapshot:
        """
        Produce an inventory snapshot as of reference_time (default: now).
        Buckets: active | expired (deleted < 24h ago) | ephemeral | persistent
        """
        now = reference_time or datetime.now(tz=timezone.utc)
        cutoff_24h = 24 * 3600

        active:     list[AssetRecord] = []
        expired:    list[AssetRecord] = []
        ephemeral:  list[AssetRecord] = []
        persistent: list[AssetRecord] = []

        for rec in self.asset_registry.values():
            if rec.is_deleted:
                age = (now - rec.deleted_at).total_seconds() if rec.deleted_at else float("inf")
                if age <= cutoff_24h:
                    expired.append(rec)
                # short-lived regardless of current state
                ttl = rec.ttl_seconds
                if ttl is not None and ttl < 600:
                    if rec not in ephemeral:
                        ephemeral.append(rec)
            else:
                active.append(rec)
                ttl = rec.ttl_seconds
                if ttl is None:
                    # Calculate time alive so far
                    start = rec.created_at or rec.first_seen
                    if start:
                        ttl = (now - start).total_seconds()
                if ttl and ttl >= 3600:
                    persistent.append(rec)

        return InventorySnapshot(
            snapshot_time = now,
            total         = len(self.asset_registry),
            active        = active,
            expired       = expired,
            ephemeral     = ephemeral,
            persistent    = persistent,
        )

    def get_events_for_resource(self, resource_id: str) -> list[UnifiedEvent]:
        return [e for e in self.event_stream if e.resource_id == resource_id]

    def get_events_for_principal(self, principal: str) -> list[UnifiedEvent]:
        return [e for e in self.event_stream if e.principal == principal]

    def summary(self) -> dict:
        snap = self.inventory_snapshot()
        novel_ids = [
            p for p, r in self.identity_registry.items()
            if getattr(r, "_novel", False)
        ]
        return {
            "total_events":           len(self.event_stream),
            "total_assets":           snap.total,
            "active_assets":          len(snap.active),
            "expired_assets":         len(snap.expired),
            "ephemeral_assets":       len(snap.ephemeral),
            "persistent_assets":      len(snap.persistent),
            "total_identities":       len(self.identity_registry),
            "novel_principals":       novel_ids,
            "sources": {
                src: sum(1 for e in self.event_stream if e.source == src)
                for src in ("cloud_audit", "k8s", "identity", "inventory")
            },
        }