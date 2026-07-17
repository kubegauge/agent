// externalsecrets.go implements KG-SE-004 (Secrets & Data): whether the cluster delegates secret
// material to an external secrets-management system instead of relying solely on native Kubernetes
// Secrets. Recognized stacks — the External Secrets Operator (syncs from Vault/AWS/GCP/Azure into
// Secrets), the HashiCorp Vault Agent Injector (injects Vault secrets straight into the pod) and
// Sealed Secrets (encrypts a Secret so the ciphertext is safe to commit to Git) — each run an
// in-cluster controller as a Deployment, so this check recognizes them by Deployment name and
// container image, the same name/image-token technique as KG-TD-001 (threatdetection.go) and
// classifyCNI (netpol.go). No CRD/dynamic-client access is needed: the controller Deployment must
// exist for any of these to function, so its presence is a stronger, cheaper signal than a dangling
// CRD with no controller behind it.
//
// Unlike KG-TD-001, absence here is INFO, not warn. KG-SE-001 already scores the core "secrets sit
// as base64 in etcd" risk hard (critical, encryption-at-rest), so a cluster that keeps native
// Secrets with encryption at rest and tight RBAC is legitimately fine. External secrets management
// is an additive best practice, not a requirement — flagging its absence as a scored warn would
// penalize a correctly-configured cluster and double-count the risk KG-SE-001 already owns. info is
// excluded from scoring (see the client's compliance.ts STATUS_WEIGHT), so this check only ever
// rewards adoption (pass) and never penalizes its absence.
package checks

import (
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// knownSecretManagers maps a distinctive lowercased token to the display name of an external
// secrets-management controller. The token is matched (substring) against a Deployment's name and
// each of its container images, so it catches both `name: external-secrets` and
// `image: ghcr.io/external-secrets/external-secrets`. Vault Agent Injector has two tokens because
// its Deployment name (vault-agent-injector) and its image (hashicorp/vault-k8s) share no substring.
var knownSecretManagers = []struct {
	token, name string
}{
	{"external-secrets", "External Secrets Operator"},
	{"vault-agent-injector", "Vault Agent Injector"},
	{"vault-k8s", "Vault Agent Injector"},
	{"sealed-secrets", "Sealed Secrets"},
}

// detectSecretManager returns the display name of the first recognized external secrets-management
// controller the Deployment matches (by name or any container image), or ok=false when none match.
func detectSecretManager(dep appsv1.Deployment) (string, bool) {
	hay := strings.ToLower(dep.Name)
	for _, c := range dep.Spec.Template.Spec.Containers {
		hay += " " + strings.ToLower(c.Image)
	}
	for _, m := range knownSecretManagers {
		if strings.Contains(hay, m.token) {
			return m.name, true
		}
	}
	return "", false
}

// ---- KG-SE-004: external secrets management present -------------------------------------------

type externalSecretsManagementCheck struct{}

func (externalSecretsManagementCheck) ID() string { return "KG-SE-004" }

// Run passes when at least one Deployment is a recognized external secrets-management controller,
// listing those Deployments as affected resources; returns info (not warn — see the package doc
// comment) when none is found.
func (externalSecretsManagementCheck) Run(snap *snapshot.Snapshot) Result {
	var found []string
	nsSet := map[string]bool{}
	for _, dep := range snap.Deployments {
		if _, ok := detectSecretManager(dep); ok {
			found = append(found, "deploy/"+dep.Namespace+"/"+dep.Name)
			nsSet[dep.Namespace] = true
		}
	}
	if len(found) == 0 {
		return Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(found)
	return Result{Status: "pass", Namespaces: sortedKeys(nsSet), AffectedResources: found}
}
