// threatdetection.go implements KG-TD-001 (Runtime Threat Detection): whether a recognized runtime
// threat-detection agent (Falco, Tetragon, Tracee, ...) is deployed as a DaemonSet. These tools
// watch syscalls/kernel events on every node to catch runtime attacks — a shell spawned in a
// container, unexpected outbound connections, privilege escalation — so they run as DaemonSets, one
// pod per node. This is the detective half of runtime security, complementing the preventive
// KG-RT-* confinement profiles (seccomp/AppArmor/SELinux, see runtime.go).
//
// KG-TD-001 is a warn (not fail) when nothing is found: a cluster may be defended by a host-level
// EDR outside Kubernetes' view, or detection may run somewhere the snapshot can't see, so — same
// "no false fail when we genuinely can't be sure" posture as netpol.go/ingress.go — absence is
// flagged as a recommendation for review, not asserted as a breach. Recognition is by DaemonSet
// name and container image, matched against a curated set of distinctive tokens (mirrors
// classifyCNI in netpol.go). Every namespace is inspected: these agents install into their own
// namespace as often as into kube-system.
package checks

import (
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// knownRuntimeDetectors maps a distinctive lowercased token to the display name of a runtime
// threat-detection tool. The token is matched (substring) against a DaemonSet's name and each of
// its container images, so it catches both `name: falco` and `image: falcosecurity/falco`.
var knownRuntimeDetectors = []struct {
	token, name string
}{
	{"falco", "Falco"},
	{"tetragon", "Tetragon"},
	{"tracee", "Tracee"},
	{"sysdig", "Sysdig"},
	{"kubearmor", "KubeArmor"},
	{"neuvector", "NeuVector"},
	{"aquasec", "Aqua"},
}

// detectRuntimeTool returns the display name of the first recognized runtime threat-detection tool
// the DaemonSet matches (by name or any container image), or ok=false when none match.
func detectRuntimeTool(ds appsv1.DaemonSet) (string, bool) {
	hay := strings.ToLower(ds.Name)
	for _, c := range ds.Spec.Template.Spec.Containers {
		hay += " " + strings.ToLower(c.Image)
	}
	for _, d := range knownRuntimeDetectors {
		if strings.Contains(hay, d.token) {
			return d.name, true
		}
	}
	return "", false
}

// ---- KG-TD-001: runtime threat detection present ----------------------------------------------

type runtimeThreatDetectionCheck struct{}

func (runtimeThreatDetectionCheck) ID() string { return "KG-TD-001" }

// Run passes when at least one DaemonSet is a recognized runtime threat-detection agent, listing
// those DaemonSets as affected resources; warns when none is found (see the package doc comment for
// why this is a warn, not a fail).
func (runtimeThreatDetectionCheck) Run(snap *snapshot.Snapshot) Result {
	var found []string
	nsSet := map[string]bool{}
	for _, ds := range snap.DaemonSets {
		if _, ok := detectRuntimeTool(ds); ok {
			found = append(found, "daemonset/"+ds.Namespace+"/"+ds.Name)
			nsSet[ds.Namespace] = true
		}
	}
	if len(found) == 0 {
		return Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(found)
	return Result{Status: "pass", Namespaces: sortedKeys(nsSet), AffectedResources: found}
}
