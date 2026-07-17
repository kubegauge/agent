// wire_integration_test.go is the wire contract's end-to-end guard: real snapshot from a fake
// clientset → Run + RbacFindings → wire.Build → validate against the generated
// schema/agent-report.v1.schema.json, and check-ids.json must mirror the registry exactly.
package checks

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/kubegauge/agent/internal/snapshot"
	"github.com/kubegauge/agent/internal/wire"
)

func TestAgentReportMatchesWireSchema(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	sch, err := compiler.Compile("../../schema/agent-report.v1.schema.json")
	if err != nil {
		t.Fatalf("compiling wire schema: %v", err)
	}

	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "apps"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx:latest"}}},
		},
	)
	snap, err := snapshot.Take(context.Background(), cs)
	if err != nil {
		t.Fatalf("snapshot.Take: %v", err)
	}

	rpt := wire.Build(snap, "test-cluster", "test", time.Now(), Run(snap), RbacFindings(snap))

	raw, err := json.Marshal(rpt)
	if err != nil {
		t.Fatalf("marshal AgentReport: %v", err)
	}
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		t.Fatalf("decode for validation: %v", err)
	}
	if err := sch.Validate(instance); err != nil {
		t.Fatalf("AgentReport does not match wire schema: %v", err)
	}
	if rpt.Kubernetes.NamespaceCount == 0 || len(rpt.Checks) == 0 {
		t.Fatalf("expected non-empty namespaces/checks, got %d/%d", rpt.Kubernetes.NamespaceCount, len(rpt.Checks))
	}
}

func TestCheckIDsFileMirrorsRegistry(t *testing.T) {
	raw, err := os.ReadFile("../../schema/check-ids.json")
	if err != nil {
		t.Fatalf("reading check-ids.json: %v", err)
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		t.Fatalf("parsing check-ids.json: %v", err)
	}
	want := make([]string, 0, len(All))
	for _, c := range All {
		want = append(want, c.ID())
	}
	sort.Strings(want)
	if len(ids) != len(want) {
		t.Fatalf("check-ids.json has %d ids, registry has %d — run `go run ./cmd/genschema`", len(ids), len(want))
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("check-ids.json[%d] = %q, registry = %q — run `go run ./cmd/genschema`", i, ids[i], want[i])
		}
	}
}
