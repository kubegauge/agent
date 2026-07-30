# KubeGauge Agent

In-cluster security posture agent for KubeGauge: scans your
Kubernetes cluster **read-only, through the API server**, and pushes the compliance report to the
KubeGauge API. One agent per cluster, installed with a single `helm install`.

> **Push-only (Phase 4, M1):** the agent makes outbound requests only — it pushes scan reports to
> the KubeGauge API and polls it for on-demand scan commands. It serves no API and has no Service:
> the old in-cluster HTTP endpoint is gone, and the only listener left is `GET /healthz` on 8787
> for kubelet probes. That port is bound on `0.0.0.0`, so other pods can reach it like any pod
> port; from v0.16.0 the chart ships an opt-in NetworkPolicy (`networkPolicy.enabled=true`) that
> denies all ingress to the agent.
> What leaves your cluster is documented in [docs/what-leaves-your-cluster.md](docs/what-leaves-your-cluster.md)
> and formalized by [schema/agent-report.v1.schema.json](schema/agent-report.v1.schema.json),
> generated from the code.

## Install

```sh
helm install kubegauge-agent oci://ghcr.io/kubegauge/charts/kubegauge-agent \
  --namespace kubegauge --create-namespace \
  --set clusterName=<name> --set ingestUrl=https://<api> --set apiKey=<kga_...>
```

See [`charts/kubegauge-agent`](charts/kubegauge-agent) for all values (RBAC surface, trivy,
resources).

## What the agent can read

A `list`-only ClusterRole over the resource types needed by the checks — pods, workloads
(Deployments/StatefulSets/DaemonSets), ServiceAccounts, Services, Namespaces, Nodes,
ResourceQuotas/LimitRanges, NetworkPolicies, Ingresses, RBAC objects, validating webhooks —
plus `get` for `kube-system/kubeadm-config` only. The agent never writes to the cluster.

**From v0.16.0, Secrets are not readable by the agent at all**: the
ClusterRole grants nothing on them, because RBAC cannot express "list metadata only" and a token
that can list Secrets cluster-wide is a credential oracle no matter how careful the code is
(`TestClusterRoleGrantsNoSecretAccess`, `TestSnapshotNeverListsSecrets`). **v0.15.0 and earlier —
the versions published today — still grant `list` on `secrets` cluster-wide**; they keep only
name/namespace/type and never send it, but the grant is real. See
[docs/what-leaves-your-cluster.md](docs/what-leaves-your-cluster.md) for what that means for you.

**ConfigMaps are read for their KEY NAMES only** — the input to KG-SE-003's credential heuristic —
and values never survive collection (`TestConfigMapValuesNeverLeaveSnapshot`). See
[the chart README](charts/kubegauge-agent/README.md#rbac-surface) for the trade v0.16.0 makes in
KG-RB-004.

## Development

```sh
make agent-dev      # kind cluster + build + deploy pushing to the host API (requires KG_API_KEY)
make agent-logs     # follow agent logs
go test ./...       # unit tests (no cluster required)
```

## License

Apache-2.0
