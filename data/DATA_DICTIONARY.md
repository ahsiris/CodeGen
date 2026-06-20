# Data Dictionary — Ephemeral Cloud Risk Detection & Incident Correlation Platform

## Dataset Overview

| File | Records | Coverage |
|---|---|---|
| cloud_audit_logs.csv | 1,000 | AWS-style API calls across 12 action types |
| kubernetes_events.csv | 1,000 | Pod, service, RBAC, and workload events |
| identity_sessions.csv | 500 | IAM role assumptions, tokens, federation events |
| resource_inventory.csv | 960 | Ephemeral resource snapshots with lifecycle times |
| ground_truth_labels.csv | 60 | Labeled correlation IDs with MITRE mappings |

### Anomaly Mix (Event-Level)
| Category | Approx % | Notes |
|---|---|---|
| Resource hijacking (crypto burst) | 5–8% of corr chains | 8 complete attack chains |
| Public exposure of ephemeral compute | 3–5% of corr chains | 5 complete attack chains |
| Identity/session abuse | 5–8% of corr chains | 7 complete attack chains |
| Legitimate autoscaling / CI/CD bursts | 40–50% | HPA, Job, CronJob events |
| Routine ephemeral lifecycle | 30–40% | Normal GetObject, PutObject, short-lived pods |

---

## FILE 1: cloud_audit_logs.csv

| Column | Type | Description |
|---|---|---|
| event_id | string | Unique event identifier (format: `evt-<hex12>`) |
| timestamp | ISO 8601 | UTC timestamp of the API call |
| principal_id | string | AWS ARN of the calling principal (IAM user, assumed-role session, or service) |
| principal_type | enum | `IAMUser` or `AssumedRole` — distinguishes human vs. role-based callers |
| action | enum | AWS API action performed (see below) |
| resource_id | string | Target resource identifier (e.g., `i-<hex12>`, `bucket-<hex12>`) |
| resource_type | enum | `ec2_instance`, `spot_instance`, `s3_bucket`, `security_group`, `volume` |
| region | enum | AWS region where the action occurred |
| tags_present | bool | Whether the resource had any resource tags at event time |
| tag_count | int | Number of tags; 0 on untagged anomalous resources |
| public_ip | string | Public IP associated with the resource (empty if private) |
| privilege_level | enum | `low`, `medium`, `high` — inferred from action + role context |
| namespace | string | Logical namespace/team boundary (mirrors Kubernetes namespaces) |
| ttl_minutes | int | Estimated or actual lifetime of the resource in minutes |
| source_ip | string | IP address originating the API call |
| user_agent | string | Tool or SDK used (`aws-cli`, `boto3`, `terraform`, `kubectl`, etc.) |
| correlation_id | string | Shared key linking all events in the same attack chain or workload burst |

**Allowed Actions:**
`RunInstances`, `TerminateInstances`, `CreateBucket`, `DeleteBucket`, `PutObject`, `GetObject`, `ListBuckets`, `AssumeRole`, `CreateSecurityGroup`, `AuthorizeSecurityGroupIngress`, `CreateVolume`, `AttachVolume`

---

## FILE 2: kubernetes_events.csv

| Column | Type | Description |
|---|---|---|
| event_id | string | Unique K8s event identifier (format: `k8s-<hex12>`) |
| timestamp | ISO 8601 | UTC timestamp of the Kubernetes event |
| namespace | string | Kubernetes namespace (`production`, `staging`, `dev`, `cicd`, `monitoring`, `analytics`) |
| pod_name | string | Name of the pod involved (format: `<app>-<ns>-<hex6>`) |
| event_type | enum | Kubernetes event kind (see below) |
| controller_owner | enum | Owner reference: `Deployment`, `Job`, `CronJob`, `HPA`, `DaemonSet`, `StatefulSet`, `None` |
| service_account | string | Kubernetes service account bound to the pod |
| image_name | string | Container image (tag included) |
| privileged | bool | Whether the container runs in privileged mode (security risk indicator) |
| host_network | bool | Whether the pod uses host networking (bypasses network policy) |
| public_exposure | bool | Whether a Service exposes this pod externally |
| node_port | int | NodePort number if publicly exposed (30000–32767); 0 if not |
| ttl_minutes | int | How long the pod existed before deletion |
| labels_present | bool | Whether the pod has Kubernetes labels (untagged pods are suspicious) |
| cpu_request | string | CPU request in millicores (e.g., `500m`) |
| memory_request | string | Memory request (e.g., `512Mi`) |
| correlation_id | string | Shared key linking related events in the same incident chain |

**Allowed Event Types:**
`PodCreated`, `PodDeleted`, `DeploymentCreated`, `ServiceCreated`, `RoleBindingCreated`, `ClusterRoleBindingCreated`, `ConfigMapCreated`, `SecretMounted`

---

## FILE 3: identity_sessions.csv

| Column | Type | Description |
|---|---|---|
| session_id | string | Unique session identifier (format: `sess-<hex16>`) |
| timestamp | ISO 8601 | UTC timestamp when session event occurred |
| principal_id | string | AWS ARN or Kubernetes service account of the identity |
| identity_type | enum | `IAMUser`, `AssumedRole`, `ServiceAccount`, `LambdaExecutionRole`, `OIDCFederated` |
| event_type | enum | `AssumeRole`, `TokenIssued`, `FederationLogin`, `ServiceAccountTokenCreated` |
| role_name | string | Target role that was assumed or token issued for |
| session_duration_minutes | int | How long the session/token is valid |
| federated | bool | Whether the identity used federated (OIDC/SAML) authentication |
| source_ip | string | IP from which the session was initiated |
| namespace | string | Namespace context for the session |
| privilege_level | enum | `low`, `medium`, `high` — inferred from role |
| correlation_id | string | Shared key linking to related audit/k8s events in same incident |

---

## FILE 4: resource_inventory.csv

| Column | Type | Description |
|---|---|---|
| resource_id | string | Unique resource identifier |
| resource_type | enum | `ec2_instance`, `spot_instance`, `s3_bucket`, `security_group`, `volume` |
| created_time | ISO 8601 | When the resource was provisioned |
| deleted_time | ISO 8601 | When the resource was terminated/deleted (empty if still alive) |
| ttl_minutes | int | Actual or expected lifetime in minutes |
| namespace | string | Logical namespace/team context |
| owner | string | Principal ARN that created the resource |
| public_exposure | bool | Whether the resource is internet-accessible |
| privilege_level | enum | `low`, `medium`, `high` — based on attached roles/policies |
| ephemeral_label | enum | `ephemeral` (TTL < 60 min) or `persistent` |

**Distribution targets met:**
- ≥ 70% resources have TTL < 60 minutes → **79.2%**
- ≥ 30% resources have TTL < 15 minutes → **40.7%**

---

## FILE 5: ground_truth_labels.csv

| Column | Type | Description |
|---|---|---|
| correlation_id | string | Links to all events in cloud_audit_logs, kubernetes_events, and identity_sessions |
| incident_type | enum | See incident types below |
| is_risky | bool | `True` = confirmed attack or exposure; `False` = benign |
| severity | enum | `critical`, `high`, `medium`, `low`, `info` |
| mitre_technique | string | MITRE ATT&CK technique ID (e.g., `T1496`) |
| description | string | Human-readable narrative of the incident |

### Incident Types

| incident_type | is_risky | MITRE | Description |
|---|---|---|---|
| `resource_hijacking` | True | T1496 | Compromised identity burst-creates spot/GPU instances for crypto mining; off-hours, untagged, short TTL, high privilege |
| `public_exposure` | True | T1190 | Privileged or debug container exposed to 0.0.0.0/0 via NodePort or misconfigured security group |
| `identity_abuse` | True | T1078 | Valid credentials used anomalously: off-hours AssumeRole, novel principals, cross-namespace access, federated login from unusual IP |
| `benign_burst` | False | — | Legitimate HPA autoscaling, CI/CD job bursts, or batch analytics that superficially resemble attacks |
| `routine_ephemeral` | False | — | Normal short-lived resources within expected lifecycle parameters (Lambda, Job pods, temporary volumes) |

---

## Correlation ID Design

Every event in all three log tables shares a `correlation_id` with related events in the same workload or attack chain. This enables:

1. **Attack chain reconstruction:** Follow a single `correlation_id` across `cloud_audit_logs → identity_sessions → kubernetes_events` to reconstruct the full incident timeline.
2. **Noise suppression:** `benign_burst` correlation IDs help train classifiers to distinguish similar-looking legitimate activity.
3. **Ephemeral evasion simulation:** Some resources in `resource_inventory` are deleted before investigation events appear in `cloud_audit_logs` (deleted_time < timestamp of follow-up events).

---

## Ambiguous Edge Cases (by design)

| Scenario | Could be benign | Could be malicious |
|---|---|---|
| 40 pods created in 2 minutes | HPA autoscaling burst | Attacker deploying cryptominer fleet |
| Spot instance with public IP | Analytics team workload | Attacker using cheap compute |
| AssumeRole at 3 AM | Scheduled Lambda function | Stolen credentials |
| Privileged pod, 5-minute TTL | Admin troubleshooting | Malicious one-shot container |

These cases appear in the dataset with ambiguous labels to test classifier robustness.
