// checks_test.go verifies registry-level invariants that don't depend on the (now platform-side)
// educational catalog: check ids are unique, and Run never leaks a nil slice for any registered
// check, even against an empty snapshot. Preserved from the pre-push-only registry_test.go, whose
// catalog-coverage test died along with the catalog package (see wire_integration_test.go's
// TestCheckIDsFileMirrorsRegistry and the platform's TestCatalogCoversEveryAgentCheck for what
// replaces that coverage).
package checks

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
	"github.com/kubegauge/agent/internal/wire"
)

func TestNoDuplicateCheckIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All {
		if seen[c.ID()] {
			t.Errorf("duplicate check id in registry: %s", c.ID())
		}
		seen[c.ID()] = true
	}
}

// TestRunOnlyEmitsSchemaStatuses: the wire schema constrains status to a closed enum, and the
// platform validates ingest against it. A check inventing a sixth status would not merely fail
// validation — before the enum existed it reached the dashboard's scoring and turned a whole
// tenant's report into NaN. This is the producer-side half of that guard.
func TestRunOnlyEmitsSchemaStatuses(t *testing.T) {
	allowed := map[string]bool{}
	for _, s := range wire.CheckStatuses {
		allowed[s] = true
	}

	snapshots := map[string]*snapshot.Snapshot{
		"empty": {},
		"every optional resource uncollected": {Uncollected: []snapshot.CollectionError{
			{Resource: "configmaps", Reason: "forbidden"},
			{Resource: "roles", Reason: "forbidden"},
			{Resource: "clusterroles", Reason: "forbidden"},
			{Resource: "rolebindings", Reason: "forbidden"},
			{Resource: "clusterrolebindings", Reason: "forbidden"},
			{Resource: "serviceaccounts", Reason: "forbidden"},
			{Resource: "ingresses", Reason: "forbidden"},
			{Resource: "resourcequotas", Reason: "forbidden"},
			{Resource: "limitranges", Reason: "forbidden"},
			{Resource: "validatingwebhookconfigurations", Reason: "forbidden"},
		}},
	}

	for name, snap := range snapshots {
		t.Run(name, func(t *testing.T) {
			for _, rc := range Run(snap) {
				if !allowed[rc.Status] {
					t.Errorf("%s emitted status %q, which is not in the wire schema's enum %v", rc.ID, rc.Status, wire.CheckStatuses)
				}
			}
		})
	}
}

// TestEveryDependencyNamesARegisteredCheck keeps resourceDependencies from rotting into a map of
// ids nobody implements any more.
func TestEveryDependencyNamesARegisteredCheck(t *testing.T) {
	registered := map[string]bool{}
	for _, c := range All {
		registered[c.ID()] = true
	}
	for resource, ids := range resourceDependencies {
		for _, id := range ids {
			if !registered[id] {
				t.Errorf("resourceDependencies[%q] names %s, which is not a registered check", resource, id)
			}
		}
	}
}

// TestUncollectedResourcesDegradeDependentChecksToNA is the honesty half of the partial-collection
// contract: a check whose input never arrived must report "na" (excluded from the score), never the
// "pass" an empty input would otherwise produce, and no other check may be affected.
func TestUncollectedResourcesDegradeDependentChecksToNA(t *testing.T) {
	snap := &snapshot.Snapshot{
		Uncollected: []snapshot.CollectionError{{Resource: "configmaps", Reason: "configmaps is forbidden"}},
	}

	byID := map[string]string{}
	for _, rc := range Run(snap) {
		byID[rc.ID] = rc.Status
	}
	if byID["KG-SE-003"] != "na" {
		t.Errorf("KG-SE-003 = %q, want na (its ConfigMaps were never collected)", byID["KG-SE-003"])
	}
	if byID["KG-SE-002"] == "na" {
		t.Error("KG-SE-002 does not read ConfigMaps and must keep its verdict")
	}
}

// TestRbacFindingsAreEmptyWhenRbacWasNotCollected: an uncollected binding list means "unknown", and
// unknown must not render as a cluster with no risky bindings.
func TestRbacFindingsAreEmptyWhenRbacWasNotCollected(t *testing.T) {
	crb := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "jenkins-admin"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "jenkins", Namespace: "ci-cd"}},
	}
	complete := &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{crb}}
	if len(RbacFindings(complete)) == 0 {
		t.Fatal("fixture is wrong: a cluster-admin binding must produce a finding")
	}

	degraded := &snapshot.Snapshot{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{crb},
		Uncollected:         []snapshot.CollectionError{{Resource: "roles", Reason: "timeout"}},
	}
	if got := RbacFindings(degraded); len(got) != 0 {
		t.Errorf("RbacFindings = %+v, want an empty list when the RBAC objects were not all collected", got)
	}
}

func TestRunNeverReturnsNilSlicesOnEmptySnapshot(t *testing.T) {
	results := Run(&snapshot.Snapshot{})
	if len(results) != len(All) {
		t.Fatalf("expected %d results (one per registered check), got %d", len(All), len(results))
	}
	for _, rc := range results {
		if rc.Namespaces == nil {
			t.Errorf("%s: Namespaces is nil, want a non-nil (possibly empty) slice", rc.ID)
		}
		if rc.AffectedResources == nil {
			t.Errorf("%s: AffectedResources is nil, want a non-nil (possibly empty) slice", rc.ID)
		}
	}
}
