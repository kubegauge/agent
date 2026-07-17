// backupdr.go implements KG-DR-001 (Backup & Disaster Recovery): whether the cluster runs a
// recognized backup/DR solution as a Deployment. A backup tool protects cluster state against
// accidental deletion, etcd corruption and ransomware that wipes API objects (MITRE T1490, "Inhibit
// System Recovery"): Velero (CNCF) backs up API objects and PersistentVolume snapshots on a schedule
// and restores them into the same or another cluster — the backbone of a DR strategy. Recognition is
// by Deployment name and container image, matched against a curated set of distinctive tokens
// (mirrors classifyCNI in netpol.go and detectSecretManager in externalsecrets.go); the controller
// Deployment must exist for backups to run, so its presence is a cheaper, stronger signal than a
// dangling Schedule CRD with no controller behind it — hence no CRD/dynamic-client access is needed.
//
// Absence is a warn, not a fail — same "no false fail when we genuinely can't be sure" posture as
// threatdetection.go/netpol.go/ingress.go. Backup may legitimately happen outside Kubernetes' view:
// volume snapshots taken at the storage layer, or etcd backups managed by the control-plane provider
// on a managed cluster. So the absence of an in-cluster backup Deployment is flagged as a
// recommendation for review, not asserted as a breach.
package checks

import (
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// knownBackupSolutions maps a distinctive lowercased token to the display name of a backup/DR
// solution. The token is matched (substring) against a Deployment's name and each of its container
// images, so it catches both `name: velero` and `image: velero/velero`.
var knownBackupSolutions = []struct {
	token, name string
}{
	{"velero", "Velero"},
	{"kasten", "Kasten K10"},
	{"trilio", "TrilioVault"},
}

// detectBackupSolution returns the display name of the first recognized backup/DR solution the
// Deployment matches (by name or any container image), or ok=false when none match.
func detectBackupSolution(dep appsv1.Deployment) (string, bool) {
	hay := strings.ToLower(dep.Name)
	for _, c := range dep.Spec.Template.Spec.Containers {
		hay += " " + strings.ToLower(c.Image)
	}
	for _, s := range knownBackupSolutions {
		if strings.Contains(hay, s.token) {
			return s.name, true
		}
	}
	return "", false
}

// ---- KG-DR-001: backup/disaster-recovery solution present -------------------------------------

type backupDisasterRecoveryCheck struct{}

func (backupDisasterRecoveryCheck) ID() string { return "KG-DR-001" }

// Run passes when at least one Deployment is a recognized backup/DR solution, listing those
// Deployments as affected resources; warns when none is found (see the package doc comment for why
// this is a warn, not a fail).
func (backupDisasterRecoveryCheck) Run(snap *snapshot.Snapshot) Result {
	var found []string
	nsSet := map[string]bool{}
	for _, dep := range snap.Deployments {
		if _, ok := detectBackupSolution(dep); ok {
			found = append(found, "deploy/"+dep.Namespace+"/"+dep.Name)
			nsSet[dep.Namespace] = true
		}
	}
	if len(found) == 0 {
		return Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(found)
	return Result{Status: "pass", Namespaces: sortedKeys(nsSet), AffectedResources: found}
}
