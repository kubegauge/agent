// chart_test.go guards the Helm chart's security- and release-critical invariants from Go, so a
// template edit that would ship a broken or over-privileged install fails `go test ./...` in the
// same run as the code it belongs to. Everything here is plain text/YAML inspection: the chart is
// a Go template, so these tests deliberately assert on the source rather than on rendered output
// (rendering would need a helm binary, which `go test` cannot assume).
package chart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const chartDir = "../../charts/kubegauge-agent"

func readChartFile(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(chartDir, rel))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(body)
}

// inlineListItems parses a flow-style YAML list ("resources: [pods, nodes]") into its items.
// Returns nil for anything else, including block-style lists.
func inlineListItems(line string) []string {
	open := strings.Index(line, "[")
	closing := strings.LastIndex(line, "]")
	if open == -1 || closing < open {
		return nil
	}
	var out []string
	for _, item := range strings.Split(line[open+1:closing], ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// TestClusterRoleGrantsNoSecretAccess is the chart-side half of the guarantee
// internal/snapshot.TestSnapshotNeverListsSecrets makes in code: Kubernetes RBAC cannot express
// "list metadata only", so the only way the agent's ServiceAccount token stops being a
// cluster-wide credential oracle is for the grant never to exist. KG-RB-006 fails a Role for
// exactly this pattern; the scanner must not ship it.
func TestClusterRoleGrantsNoSecretAccess(t *testing.T) {
	for i, line := range strings.Split(readChartFile(t, "templates/rbac.yaml"), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- resources:") && !strings.HasPrefix(trimmed, "resources:") {
			continue
		}
		for _, res := range inlineListItems(trimmed) {
			if res == "secrets" || res == "*" {
				t.Errorf("templates/rbac.yaml:%d grants %q — the agent must never be able to read Secrets: %s", i+1, res, trimmed)
			}
		}
	}
}
