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

Install the **published OCI chart**, as above. Installing from a git checkout of `main` works, but
`main` describes the *next* release: its `appVersion` names an image tag that only exists once that
release is cut, and its templates assume that agent (the RBAC surface and the image move together).
For a checkout install between releases, pin an image explicitly with `--set image.tag=v0.15.0` —
and read the release notes first, because an older agent may need grants this chart no longer
creates.

## Values

| Key | Default | Description |
|---|---|---|
| `clusterName` | release name | Cluster name shown in the dashboard |
| `ingestUrl` | — (required) | Base URL of the KubeGauge API |
| `apiKey` | — (required) | Cluster API key (stored in a chart-managed Secret) |
| `scanInterval` | `1h` | Interval between pushed scans (plan minimums enforced server-side) |
| `collectTimeout` | `10m` | Budget for one (paginated) collection pass over the API server |
| `rbac.readConfigMapKeys` | `true` | `list configmaps` for KG-SE-003's key-name heuristic; `false` drops the verb and the check reports N/A |
| `image.repository` / `image.tag` | ghcr / appVersion | Agent image |
| `trivy.enabled` | `true` | Image vulnerability scanning (KG-SU-003) |
| `resources` | requests 100m/128Mi, limits 1/1Gi | Hardened-by-default pod sizing |

## Large clusters, and what happens when a read fails

Every list is paginated, and the whole pass runs inside `collectTimeout` (10m by default, not the
30s that used to make big clusters fail every scan forever). Resources split in two: the core ones
(nodes, namespaces, pods, workloads, NetworkPolicies, Services) whose absence would make the report
describe a cluster that does not exist — a failure there aborts the pass and the agent retries —
and the rest, whose absence only costs the checks that read them. Those failures are recorded, the
dependent checks report **N/A** instead of a "pass" faked from empty input, and the reason is
logged. That is what makes trimming a grant (`rbac.readConfigMapKeys=false`) a supported choice
rather than a broken install.

## RBAC surface

A `list`-only ClusterRole over the resource types the checks need (pods, workloads,
ServiceAccounts, Services, Namespaces, Nodes, quotas, NetworkPolicies, Ingresses, RBAC objects,
validating webhooks) plus `get` on `kube-system/kubeadm-config` only. The agent never writes to
your cluster.

**Secrets are not in it at all.** Kubernetes RBAC has no "list metadata only" verb, so a
`list secrets` grant would make the agent's ServiceAccount token a cluster-wide credential oracle
for anyone who reached the pod — regardless of what the agent's own code does with the response.
That grant is the exact pattern KG-RB-006 fails a Role for, so the scanner does not ship it
(`TestClusterRoleGrantsNoSecretAccess`, `TestSnapshotNeverListsSecrets`). The one check that needed
to know which namespaces hold Secrets (KG-RB-004) now infers it from references it can already see
— secret volumes, `envFrom`/`secretKeyRef`, `imagePullSecrets`, ServiceAccount secrets, Ingress TLS
— which under-reports namespaces whose Secrets are unused. That is a deliberate trade.

**ConfigMaps are read, key names only.** KG-SE-003 matches ConfigMap KEY NAMES against a
credential-looking pattern, and no metadata-only projection the API server can serve carries them,
so this one grant cannot be reduced without dropping the check. Values are discarded in the same
loop that lists them and never reach a report or a log (`TestConfigMapValuesNeverLeaveSnapshot`).

## Expected self-findings

The agent's namespace intentionally shows up in its own report (dogfooding): NetworkPolicy
coverage (KG-NP-*) and missing ResourceQuota/LimitRange (KG-QT-*) against the release namespace.
If your cluster grants anyone `create pods` in that namespace, expect KG-RB-004 to warn about it
too: the release namespace holds the API-key Secret the agent mounts.
