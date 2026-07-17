# What leaves your cluster

The KubeGauge agent is **outbound-only**: it accepts no inbound connections (no Service, no
exposed API — only a pod-local `GET /healthz` for kubelet probes) and sends exactly ONE kind of
payload to exactly ONE destination: an `AgentReport` to the `ingestUrl` you configure,
authenticated by your cluster's API key over TLS.

The payload is formalized by [`schema/agent-report.v1.schema.json`](../schema/agent-report.v1.schema.json),
**generated from the Go structs** in [`internal/wire`](../internal/wire) — the schema cannot drift
from the code (test-enforced). This document is the human-readable tour of every field.

## Field by field

| Field | Content | Example |
|---|---|---|
| `schemaVersion`, `agentVersion` | Wire version + agent build | `1`, `v0.12.0` |
| `clusterName` | The name YOU configured in the chart | `prod-east` |
| `takenAt` | Scan timestamp (UTC) | `2026-07-17T12:00:00Z` |
| `kubernetes` | Version, distribution heuristic, node/namespace counts | `v1.33.1`, `eks`, `12`, `31` |
| `checks[]` | Per check id: `status` (pass/fail/warn/info), affected `namespaces`, `affectedResources` (kind/namespace/name strings), and for the image-scan check `imageFindings` (image refs + CVE counts + top CVE ids) | `{"id":"KG-NP-001","status":"fail","namespaces":["apps"],...}` |
| `namespaces[]` | Name, PSA labels, pod count, default-deny flags | `{"name":"apps","psaEnforce":null,...}` |
| `workloads[]` | Workload identity (kind/namespace/name) + security posture booleans (runAsNonRoot, seccomp, etc.) | — |
| `rbacFindings[]` | Risky bindings: subject, binding, role names + reason | — |
| `network` | The NetworkPolicy evaluation graph: workload/service nodes and allowed/denied flows with the policy name responsible | — |

## What NEVER leaves

- **Secret and ConfigMap VALUES.** The snapshot keeps metadata only (name/namespace/type). This is
  enforced by `TestSecretValuesNeverLeaveSnapshot` in `internal/snapshot` — the test fails the
  build if a code change ever makes a secret value reachable from the snapshot.
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

The read surface is a `list`-only ClusterRole (plus `get` on `kube-system/kubeadm-config`):
`helm template` the chart and read `rbac.yaml`. Then read `internal/snapshot` (what is collected),
`internal/checks` (what is computed) and `internal/wire` (what is sent). That's the whole pipeline.
