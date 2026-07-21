# kubegauge-agent (Helm chart)

Installs the KubeGauge in-cluster agent: a **read-only, outbound-only** scanner that snapshots
your cluster through the API server, runs the compliance checks, and pushes the raw results to
the KubeGauge API. No inbound connections, no Service, no exposed ports (only a pod-local
`/healthz` for probes). What leaves the cluster is documented field by field in
[`docs/what-leaves-your-cluster.md`](../../docs/what-leaves-your-cluster.md) and formalized by
[`schema/agent-report.v1.schema.json`](../../schema/agent-report.v1.schema.json).

## Install

```sh
helm install kubegauge-agent oci://ghcr.io/kubegauge/charts/kubegauge-agent \
  --namespace kubegauge --create-namespace \
  --set clusterName=<name shown in the dashboard> \
  --set ingestUrl=https://<your kubegauge api> \
  --set apiKey=<kga_... from the dashboard wizard>
```

## Values

| Key | Default | Description |
|---|---|---|
| `clusterName` | release name | Cluster name shown in the dashboard |
| `ingestUrl` | — (required) | Base URL of the KubeGauge API |
| `apiKey` | — (required) | Cluster API key (stored in a chart-managed Secret) |
| `scanInterval` | `1h` | Interval between pushed scans (plan minimums enforced server-side) |
| `image.repository` / `image.tag` | ghcr / appVersion | Agent image |
| `trivy.enabled` | `true` | Image vulnerability scanning (KG-SU-003) |
| `resources` | requests 100m/128Mi, limits 1/1Gi | Hardened-by-default pod sizing |

## RBAC surface

A `list`-only ClusterRole over the resource types the checks need (pods, workloads,
ServiceAccounts, Services, Namespaces, Nodes, quotas, NetworkPolicies, Ingresses, RBAC objects,
validating webhooks) plus `get` on `kube-system/kubeadm-config` only. **Secrets and ConfigMaps are
metadata-only** — names/namespaces/types, never values (test-enforced). The agent never writes to
your cluster.

## Expected self-findings

The agent's namespace intentionally shows up in its own report (dogfooding): NetworkPolicy
coverage (KG-NP-*) and missing ResourceQuota/LimitRange (KG-QT-*) against the release namespace.
