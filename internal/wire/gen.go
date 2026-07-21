// gen.go generates the versioned JSON Schema for AgentReport from the Go structs — the single
// source of truth for what leaves the cluster. cmd/genschema writes it to schema/; schema_test.go
// fails when the committed file drifts from the structs.
package wire

import (
	"encoding/json"

	"github.com/invopop/jsonschema"
)

// GenerateSchema reflects AgentReport into a JSON Schema document (2-space indented, trailing
// newline — stable bytes for the drift test).
func GenerateSchema() ([]byte, error) {
	r := &jsonschema.Reflector{}
	sch := r.Reflect(&AgentReport{})
	sch.ID = "https://raw.githubusercontent.com/kubegauge/agent/main/schema/agent-report.v1.schema.json"
	sch.Title = "KubeGauge AgentReport v1"
	sch.Description = "Everything the kubegauge-agent ever sends out of your cluster. See docs/what-leaves-your-cluster.md."
	out, err := json.MarshalIndent(sch, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
