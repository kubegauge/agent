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

	"k8s.io/apimachinery/pkg/api/resource"
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

// TestApiKeyCanComeFromAnExistingSecret: passing apiKey inline writes it into Helm's release
// Secret, where `helm get values` can read it back. Operators must be able to hand the chart a
// Secret it never sees the contents of — without the inline path regressing.
func TestApiKeyCanComeFromAnExistingSecret(t *testing.T) {
	secret := readChartFile(t, "templates/secret.yaml")
	if !strings.Contains(secret, "if not .Values.existingSecret") {
		t.Error("templates/secret.yaml must not create a Secret when existingSecret is set")
	}
	if !strings.Contains(secret, "required") || !strings.Contains(secret, ".Values.apiKey") {
		t.Error("templates/secret.yaml must still require apiKey when it does create the Secret")
	}

	deployment := readChartFile(t, "templates/deployment.yaml")
	if !strings.Contains(deployment, `include "kubegauge-agent.apiKeySecretName"`) {
		t.Error("templates/deployment.yaml must mount whichever Secret holds the key, via the helper")
	}
	// The key is mounted as a file and passed with --api-key-file: never an env var, never an arg.
	// Reading .Values.apiKey to decide whether it is SET is fine (the guard above does); emitting
	// its value into the pod spec is not.
	for _, emission := range []string{"{{ .Values.apiKey", "{{- .Values.apiKey", "{{.Values.apiKey"} {
		if strings.Contains(deployment, emission) {
			t.Errorf("templates/deployment.yaml emits the API key value (%s) — it must only ever be a mounted file", emission)
		}
	}
	if !strings.Contains(deployment, "--api-key-file=") {
		t.Error("templates/deployment.yaml must keep passing the key as a file path")
	}
}

// TestEphemeralStorageIsBounded: trivy downloads databases measured in gigabytes into an emptyDir
// (1.14 GiB extracted for the vulnerability database, another 1.39 GiB for the Java one, as
// published on 2026-07-30). Without a sizeLimit on the volume and an ephemeral-storage limit on
// the container, the agent can fill a node's disk and evict its neighbours — a scanner doing that
// to the cluster it is auditing is not a good look. How LARGE those bounds have to be is a
// separate question, and TestEphemeralStorageLimitClearsBothVolumes below is where it lives:
// this test passed unchanged while 0.16.0 shipped a cache limit smaller than the databases.
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

// scalarAt walks values.yaml as a plain indented mapping and returns the scalar at path
// ("resources", "limits", "ephemeral-storage"), or ok=false. Enough YAML for a hand-written values
// file of scalars and nested maps, and no more: block lists, flow maps and anchors are out of
// scope, which is fine because the keys this file asserts on are none of those.
func scalarAt(body string, path ...string) (string, bool) {
	lines := strings.Split(body, "\n")
	for len(path) > 0 {
		blockIndent, matched := -1, false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if blockIndent == -1 {
				blockIndent = indent // the first key sets the depth of the block being searched
			}
			if indent < blockIndent {
				break // the block ended without the key
			}
			if indent > blockIndent {
				continue // nested under a sibling key
			}
			key, value, ok := strings.Cut(trimmed, ":")
			if !ok || strings.TrimSpace(key) != path[0] {
				continue
			}
			if len(path) == 1 {
				return strings.Trim(strings.TrimSpace(value), `"'`), true
			}
			lines, path, matched = lines[i+1:], path[1:], true // descend into this key's block
			break
		}
		if !matched {
			return "", false
		}
	}
	return "", false
}

// valuesQuantity reads a Kubernetes quantity ("8Gi") out of values.yaml, failing the test if the
// key is absent or unparseable — either would silently disable the comparisons below.
func valuesQuantity(t *testing.T, path ...string) resource.Quantity {
	t.Helper()
	raw, ok := scalarAt(readChartFile(t, "values.yaml"), path...)
	if !ok {
		t.Fatalf("values.yaml has no %s", strings.Join(path, "."))
	}
	q, err := resource.ParseQuantity(raw)
	if err != nil {
		t.Fatalf("values.yaml %s = %q is not a quantity: %v", strings.Join(path, "."), raw, err)
	}
	return q
}

// TestScalarAtReadsNestedValues tests the reader, so a values.yaml reshuffle that made it return
// nothing would fail here rather than quietly turning the guard below into a no-op.
func TestScalarAtReadsNestedValues(t *testing.T) {
	const sample = `top: first
# a comment, and a blank line follow

outer:
  inner:
    leaf: 6Gi
    other: 1
  sibling: no
after: last
`
	cases := []struct {
		path []string
		want string
		ok   bool
	}{
		{[]string{"top"}, "first", true},
		{[]string{"after"}, "last", true},
		{[]string{"outer", "inner", "leaf"}, "6Gi", true},
		{[]string{"outer", "sibling"}, "no", true},
		{[]string{"outer", "missing"}, "", false},
		{[]string{"outer", "inner", "top"}, "", false},   // must not escape the block it descended into
		{[]string{"outer", "inner", "after"}, "", false}, // nor fall through to a shallower key
		{[]string{"absent"}, "", false},
	}
	for _, tc := range cases {
		got, ok := scalarAt(sample, tc.path...)
		if got != tc.want || ok != tc.ok {
			t.Errorf("scalarAt(%v) = %q, %v; want %q, %v", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

// logHeadroom is how much of the ephemeral-storage limit must stay free after both emptyDir
// volumes are counted. Container logs and the container's writable layer are charged to the same
// limit, so a limit merely EQUAL to the volumes guarantees eviction eventually — 0.16.0 shipped
// exactly that (limits 3Gi against cacheSizeLimit 2Gi + tmpSizeLimit 1Gi).
var logHeadroom = resource.MustParse("1Gi")

// maxStorageRequest keeps requests.ephemeral-storage schedulable. The request is what the
// scheduler subtracts from a node's allocatable storage; the limit is only an eviction threshold
// and costs nothing at scheduling time. Raising the limit must never drag the request up with it,
// or the agent stops fitting on small nodes.
var maxStorageRequest = resource.MustParse("1Gi")

// TestEphemeralStorageLimitClearsBothVolumes is the guard for the 0.16.0 regression. Two defects
// shipped together there: cacheSizeLimit (2Gi) was below the databases trivy keeps in that volume,
// so every agent with trivy enabled entered a permanent eviction loop on first scan; and the
// ephemeral-storage limit (3Gi) was exactly cacheSizeLimit + tmpSizeLimit, leaving nothing for the
// logs that count against it, so even correctly sized volumes would have been evicted in the end.
// The absolute sizes are argued in values.yaml; what is mechanical, and therefore guarded here, is
// that the outer bound stays above the inner ones with room to spare.
func TestEphemeralStorageLimitClearsBothVolumes(t *testing.T) {
	cache := valuesQuantity(t, "cacheSizeLimit")
	tmp := valuesQuantity(t, "tmpSizeLimit")
	limit := valuesQuantity(t, "resources", "limits", "ephemeral-storage")
	request := valuesQuantity(t, "resources", "requests", "ephemeral-storage")

	needed := cache.DeepCopy()
	needed.Add(tmp)
	needed.Add(logHeadroom)
	if limit.Cmp(needed) < 0 {
		t.Errorf("resources.limits.ephemeral-storage = %s, but cacheSizeLimit (%s) + tmpSizeLimit (%s) + %s of headroom for logs = %s: the pod gets evicted on the pod-level limit even when both volumes stay inside theirs",
			limit.String(), cache.String(), tmp.String(), logHeadroom.String(), needed.String())
	}
	if request.Cmp(maxStorageRequest) > 0 {
		t.Errorf("resources.requests.ephemeral-storage = %s, above the %s ceiling: the request is reserved at scheduling time, so raising it with the limit stops the agent fitting on small nodes",
			request.String(), maxStorageRequest.String())
	}
	if request.Cmp(limit) > 0 {
		t.Errorf("resources.requests.ephemeral-storage (%s) exceeds the limit (%s)", request.String(), limit.String())
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
