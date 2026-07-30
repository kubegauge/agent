# kubegauge-agent (Helm chart)

Installs the KubeGauge in-cluster agent: a **read-only, outbound-only** scanner that snapshots
your cluster through the API server, runs the compliance checks, and pushes the raw results to
the KubeGauge API. No Service, no exposed API — the only listener is `/healthz` on 8787 for
kubelet probes, and `networkPolicy.enabled=true` (chart 0.16.0+) denies all ingress to it.
What leaves the cluster is documented field by field in
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
For a checkout install between releases, pin an image explicitly with `--set image.tag=v0.16.0` —
and read the release notes first, because an older agent may need grants this chart no longer
creates.

## Values

This table describes the chart in this checkout (**0.16.1, unreleased**). It is a fix release over
0.16.0 and changes nothing but the storage sizes: 0.16.0 bounded the two cache volumes below what
trivy's databases actually need, which put the agent into a permanent eviction loop on every
cluster with image scanning on. See `cacheSizeLimit` below and the reasoning in `values.yaml`.

| Key | Default | Description |
|---|---|---|
| `clusterName` | release name | Cluster name shown in the dashboard |
| `ingestUrl` | — (required) | Base URL of the KubeGauge API (must be `https://`) |
| `allowInsecureHttp` | `false` | Permit an `http://` ingestUrl — development only, the API key then travels in cleartext |
| `apiKey` | — (required unless `existingSecret`) | Cluster API key (stored in a chart-managed Secret) |
| `existingSecret` / `existingSecretKey` | `""` / `api-key` | Use a Secret you manage instead; the chart then never handles the key |
| `scanInterval` | `1h` | Interval between pushed scans (plan minimums enforced server-side) |
| `collectTimeout` | `10m` | Budget for one (paginated) collection pass over the API server |
| `rbac.readConfigMapKeys` | `true` | `list configmaps` for KG-SE-003's key-name heuristic; `false` drops the verb and the check reports N/A |
| `image.repository` / `image.tag` | ghcr / appVersion | Agent image |
| `trivy.enabled` | `true` | Image vulnerability scanning (KG-SU-003) |
| `resources` | requests 100m/128Mi/512Mi, limits 1/1Gi/12Gi | Hardened-by-default pod sizing (cpu/memory/ephemeral-storage). The storage *request* stays small so the pod schedules on modest nodes; the *limit* has to clear `cacheSizeLimit` + `tmpSizeLimit` plus room for logs |
| `cacheSizeLimit` / `tmpSizeLimit` | `8Gi` / `3Gi` | `sizeLimit` on the two emptyDir volumes. trivy's databases live in the first (1.14 GiB extracted for vulnerabilities, 1.39 GiB more for Java once a jar is scanned); the second takes their compressed downloads and the scratch space for unpacking images |
| `networkPolicy.enabled` | `false` | Deny all ingress to the agent pod (opt-in: kubelet probes come from the node, and CNIs differ on whether policy applies to them) |

## Large clusters, and what happens when a read fails

Every list is paginated, and the whole pass runs inside `collectTimeout` (10m by default, not the
30s that used to make big clusters fail every scan forever). Resources split in two: the core ones
(nodes, namespaces, pods, workloads, NetworkPolicies, Services) whose absence would make the report
describe a cluster that does not exist — a failure there aborts the pass and the agent retries —
and the rest, whose absence only costs the checks that read them. Those failures are recorded, the
dependent checks report **N/A** instead of a "pass" faked from empty input, and the reason is
logged. That is what makes trimming a grant (`rbac.readConfigMapKeys=false`) a supported choice
rather than a broken install.

## Where the API key lives

At runtime the key is only ever a file: mounted from a Secret, read through `--api-key-file`,
re-read on every request so a rotation takes effect without a restart, never an environment
variable, never an argument, never logged. `kubectl describe pod` shows nothing.

Getting it there is the part with a trade-off.

- `--set apiKey=kga_...` is the simple path, and the one the dashboard wizard prints. Helm stores
  the values you pass in the release Secret, so anyone who can read that (or run
  `helm get values`) can recover the key.
- `--set existingSecret=my-secret` (chart 0.16.0+) points the agent at a Secret **you** create —
  from a secrets manager, sealed-secrets, external-secrets, whatever you already run. The chart
  creates no Secret and the key never passes through Helm. Use `existingSecretKey` if the key
  inside it is not called `api-key`.

Either way, rotating means updating the Secret; the agent picks it up on its next request.

## RBAC surface

A `list`-only ClusterRole over the resource types the checks need (pods, workloads,
ServiceAccounts, Services, Namespaces, Nodes, quotas, NetworkPolicies, Ingresses, RBAC objects,
validating webhooks) plus `get` on `kube-system/kubeadm-config` only. The agent never writes to
your cluster.

**Secrets are not in it at all — from chart 0.16.0.** Kubernetes RBAC has no "list metadata only"
verb, so a `list secrets` grant would make the agent's ServiceAccount token a cluster-wide
credential oracle for anyone who reached the pod — regardless of what the agent's own code does
with the response. That grant is the exact pattern KG-RB-006 fails a Role for, so the scanner no
longer ships it (`TestClusterRoleGrantsNoSecretAccess`, `TestSnapshotNeverListsSecrets`). The one
check that needed to know which namespaces hold Secrets (KG-RB-004) now infers it from references
it can already see — secret volumes, `envFrom`/`secretKeyRef`, `imagePullSecrets`, ServiceAccount
secrets, Ingress TLS — which under-reports namespaces whose Secrets are unused. That is a
deliberate trade.

**Chart 0.15.0 and earlier still grant it.** If that is what you installed from the OCI chart, your
agent's ServiceAccount can list every Secret in the cluster. Removing the rule by hand does not
work on a v0.15.0 agent — it treats the resulting 403 as fatal and every scan fails. Upgrading is
the fix, and the version to upgrade to is **0.16.1**: 0.16.0 dropped the grant but sized the cache
volumes below trivy's databases, so its agent is evicted in a loop wherever image scanning is on.

**ConfigMaps are read, key names only.** KG-SE-003 matches ConfigMap KEY NAMES against a
credential-looking pattern, and no metadata-only projection the API server can serve carries them,
so this one grant cannot be reduced without dropping the check. Values are discarded in the same
loop that lists them and never reach a report or a log (`TestConfigMapValuesNeverLeaveSnapshot`).

## Expected self-findings

The agent's namespace intentionally shows up in its own report (dogfooding): NetworkPolicy
coverage (KG-NP-*) and missing ResourceQuota/LimitRange (KG-QT-*) against the release namespace.
If your cluster grants anyone `create pods` in that namespace, expect KG-RB-004 to warn about it
too: the release namespace holds the API-key Secret the agent mounts.

**On chart 0.15.0 and earlier, KG-RB-006 fails on the agent's own ClusterRole** — it grants `list`
on `secrets`, which is exactly what that check looks for. That self-finding is correct and the
scanner earned it; chart 0.16.0 removes the grant instead of exempting the agent from its own
check, and no version has ever exempted it.
