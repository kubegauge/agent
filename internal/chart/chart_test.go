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

// chartField reads a top-level scalar out of Chart.yaml ("version: 0.16.0"), unquoted.
func chartField(t *testing.T, name string) string {
	t.Helper()
	for _, line := range strings.Split(readChartFile(t, "Chart.yaml"), "\n") {
		if value, ok := strings.CutPrefix(line, name+":"); ok {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	t.Fatalf("Chart.yaml has no %s field", name)
	return ""
}

// TestChartVersionsAgree stops the release drift that shipped chart 0.13.0 with an image tag that
// was never published: CI packages the chart as --version ${TAG#v} and publishes the image as
// agent:$TAG, so `version` and `appVersion` must be the same release expressed both ways. The
// tag-side half of this (does the release tag match Chart.yaml at all?) is enforced by the
// "chart version matches the tag" step in .github/workflows/ci.yml.
func TestChartVersionsAgree(t *testing.T) {
	version, appVersion := chartField(t, "version"), chartField(t, "appVersion")
	if appVersion != "v"+version {
		t.Errorf("Chart.yaml appVersion = %q, want %q (the published image tag for chart version %s)", appVersion, "v"+version, version)
	}
}

// TestDeploymentResolvesImageThroughHelper keeps the "v" normalization from being bypassed by a
// future edit that inlines the tag again.
func TestDeploymentResolvesImageThroughHelper(t *testing.T) {
	deployment := readChartFile(t, "templates/deployment.yaml")
	if !strings.Contains(deployment, `include "kubegauge-agent.image"`) {
		t.Error(`templates/deployment.yaml must build the image reference with the "kubegauge-agent.image" helper`)
	}
	if strings.Contains(deployment, ".Values.image.tag") {
		t.Error("templates/deployment.yaml must not read .Values.image.tag directly — the helper normalizes it")
	}
}

// TestEphemeralStorageIsBounded: trivy downloads a CVE database measured in hundreds of megabytes
// into an emptyDir. Without a sizeLimit on the volume and an ephemeral-storage limit on the
// container, the agent can fill a node's disk and evict its neighbours — a scanner doing that to
// the cluster it is auditing is not a good look.
func TestEphemeralStorageIsBounded(t *testing.T) {
	deployment := readChartFile(t, "templates/deployment.yaml")
	if strings.Contains(deployment, "emptyDir: {}") {
		t.Error("templates/deployment.yaml has an emptyDir with no sizeLimit")
	}
	for _, want := range []string{"sizeLimit: {{ .Values.cacheSizeLimit }}", "sizeLimit: {{ .Values.tmpSizeLimit }}"} {
		if !strings.Contains(deployment, want) {
			t.Errorf("templates/deployment.yaml is missing %q", want)
		}
	}

	values := readChartFile(t, "values.yaml")
	if strings.Count(values, "ephemeral-storage:") < 2 {
		t.Error("values.yaml must set ephemeral-storage in both requests and limits")
	}
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
