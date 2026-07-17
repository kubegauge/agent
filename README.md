# KubeGauge Agent

In-cluster security posture agent for KubeGauge: scans your
Kubernetes cluster **read-only, through the API server**, and pushes the compliance report to the
KubeGauge API. One agent per cluster, installed with a single `helm install`.

> **Push-only (Phase 4, M1):** the agent makes outbound requests only — it pushes scan reports to
> the KubeGauge API and polls it for on-demand scan commands. **No inbound connections, ever**
> (the old in-cluster HTTP endpoint is gone; only `GET /healthz` remains, pod-local, for probes).
> What leaves your cluster is documented in [docs/what-leaves-your-cluster.md](docs/what-leaves-your-cluster.md)
> and formalized by [schema/agent-report.v1.schema.json](schema/agent-report.v1.schema.json),
> generated from the code.

## Install

```sh
helm install kubegauge-agent oci://ghcr.io/slackerwx/charts/kubegauge-agent \
  --namespace kubegauge --create-namespace \
  --set clusterName=<name> --set ingestUrl=https://<api> --set apiKey=<kga_...>
```

See [`charts/kubegauge-agent`](charts/kubegauge-agent) for all values (RBAC surface, trivy,
resources).

## What the agent can read

A `list`-only ClusterRole over the resource types needed by the checks — pods, workloads
(Deployments/StatefulSets/DaemonSets), ServiceAccounts, Services, Namespaces, Nodes,
ResourceQuotas/LimitRanges, NetworkPolicies, Ingresses, RBAC objects, validating webhooks —
plus `get` for `kube-system/kubeadm-config` only. **Secrets and ConfigMaps are metadata-only**:
the snapshot retains name/namespace/type and never reads values — enforced by
`TestSecretValuesNeverLeaveSnapshot`. The agent never writes to the cluster.

## Development

```sh
make agent-dev      # kind cluster + build + deploy pushing to the host API (requires KG_API_KEY)
make agent-logs     # follow agent logs
go test ./...       # unit tests (no cluster required)
```

## License

Apache-2.0
