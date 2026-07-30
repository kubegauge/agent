# What leaves your cluster

> **Which version this describes.** The newest published agent and chart are **v0.16.1**, and this
> document describes them. Items marked *from v0.16.0* changed what the agent can read, so they do
> **not** describe an older agent still running in your cluster — both states are spelled out below.
> Upgrade straight to v0.16.1: v0.16.0 sized the trivy cache volume below the databases trivy
> actually downloads, so its pod is evicted in a loop.

The KubeGauge agent is **outbound-only**: it makes only outbound requests and exposes no Service
and no API. The single listener is a pod-local `GET /healthz` on port 8787 for kubelet probes;
it is reachable from inside the cluster like any other pod port, and the chart ships an optional
NetworkPolicy (from v0.16.0) to close even that. It sends exactly ONE kind of payload to exactly
ONE destination: an `AgentReport` to the `ingestUrl` you configure, authenticated by your cluster's
API key over TLS.

The payload is formalized by [`schema/agent-report.v1.schema.json`](../schema/agent-report.v1.schema.json),
**generated from the Go structs** in [`internal/wire`](../internal/wire) — the schema cannot drift
from the code (test-enforced). This document is the human-readable tour of every field.

## Field by field

| Field | Content | Example |
|---|---|---|
| `schemaVersion`, `agentVersion` | Wire version + agent build | `1`, `v0.13.0` |
| `clusterName` | The name YOU configured in the chart | `prod-east` |
| `takenAt` | Scan timestamp (UTC) | `2026-07-17T12:00:00Z` |
| `kubernetes` | Version, distribution heuristic, node/namespace counts | `v1.33.1`, `eks`, `12`, `31` |
| `checks[]` | Per check id: `status` (pass/fail/warn/info/na — `na` means the check was not applicable or could not be evaluated, and it is excluded from the score), affected `namespaces`, `affectedResources` (kind/namespace/name strings), and for the image-scan check `imageFindings` (image refs + CVE counts + top CVE ids) | `{"id":"KG-NP-001","status":"fail","namespaces":["apps"],...}` |
| `namespaces[]` | Name, PSA labels, pod count, default-deny flags | `{"name":"apps","psaEnforce":null,...}` |
| `workloads[]` | Workload identity (kind/namespace/name) + security posture booleans (runAsNonRoot, seccomp, etc.) | — |
| `rbacFindings[]` | Risky bindings: subject, binding, role names + reason, plus the binding's `namespace` for a RoleBinding (absent for a cluster-scoped ClusterRoleBinding) | — |
| `network` | The NetworkPolicy evaluation graph: workload/service nodes and allowed/denied flows with the policy name responsible | — |

## What NEVER leaves

- **Secret VALUES**, in every version. Nothing a Secret contains has ever been kept, serialized or
  logged.
- **Anything about your Secrets at all, including their names — *from v0.16.0*.** That version
  removes `secrets` from the ClusterRole entirely, so the agent cannot read one even by accident
  (`TestSnapshotNeverListsSecrets`, `TestClusterRoleGrantsNoSecretAccess`).
  **In v0.15.0 and earlier — which is what you install today — the ClusterRole DOES grant `list` on
  `secrets` cluster-wide.** Those versions list Secrets and keep only name/namespace/type in
  memory, never sending them; but the grant exists, so the agent's ServiceAccount token can read
  every Secret in the cluster, and anyone who reaches that token can too. If that matters to you,
  wait for v0.16.0, or remove `secrets` from the ClusterRole yourself — on v0.15.0 that makes every
  scan fail (the collector treats the 403 as fatal), which is itself fixed in v0.16.0.
- **ConfigMap VALUES.** ConfigMaps are listed for their KEY NAMES only (KG-SE-003's credential
  heuristic); values are discarded in the same loop that lists them, enforced by
  `TestConfigMapValuesNeverLeaveSnapshot` in `internal/snapshot` — the test fails the build if a
  code change ever makes a value reachable from the snapshot.
- **Pod environment variables, command lines, volume contents, logs.** Never collected.
- **Manifests.** The agent reports *verdicts about* your objects (names + booleans + counts),
  not the objects themselves.
- **Educational content in reverse.** The explanation/remediation texts you see in the dashboard
  live server-side; nothing editorial travels from your cluster.

## What DOES leave (be aware)

- **Object names** (namespaces, workloads, roles, bindings, images). Names can be sensitive in
  some organizations — review the schema before installing if that matters to you.
- **Image references and CVE ids** for the vulnerability check (trivy runs IN-cluster; only the
  summary counts and top CVE ids are reported, never SBOMs).

## When and how

- One push per `scanInterval` (default 1h; your plan's minimum is enforced server-side), plus one
  push after an on-demand scan you trigger in the dashboard.
- A ~30s `GET /v1/agent/commands` poll (empty-handed most of the time) doubles as the heartbeat.
- Both calls go to your configured `ingestUrl`, TLS, `Authorization: Bearer kga_...` — revoke the
  key in the dashboard and the agent is cut off immediately (it backs off quietly; no crash-loop).

## Verify it yourself

The read surface is a `list`-only ClusterRole (plus `get` on `kube-system/kubeadm-config`) — with no
`secrets` entry anywhere in it from v0.16.0, and with one in v0.15.0 and earlier. Do not take this
document's word for it: `helm template` **the chart version you are installing** and read
`rbac.yaml`. Then read `internal/snapshot` (what is collected),
`internal/checks` (what is computed) and `internal/wire` (what is sent). That's the whole pipeline.
