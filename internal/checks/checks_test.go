// checks_test.go verifies registry-level invariants that don't depend on the (now platform-side)
// educational catalog: check ids are unique, and Run never leaks a nil slice for any registered
// check, even against an empty snapshot. Preserved from the pre-push-only registry_test.go, whose
// catalog-coverage test died along with the catalog package (see wire_integration_test.go's
// TestCheckIDsFileMirrorsRegistry and the platform's TestCatalogCoversEveryAgentCheck for what
// replaces that coverage).
package checks

import (
	"testing"

	"github.com/kubegauge/agent/internal/snapshot"
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
