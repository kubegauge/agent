// schema_test.go locks the committed schema file to the Go structs (drift guard: regenerating must
// be a no-op) — the public transparency claim is "the schema IS the code".
package wire

import (
	"bytes"
	"os"
	"testing"
)

func TestCommittedSchemaMatchesStructs(t *testing.T) {
	want, err := GenerateSchema()
	if err != nil {
		t.Fatalf("GenerateSchema: %v", err)
	}
	got, err := os.ReadFile("../../schema/agent-report.v1.schema.json")
	if err != nil {
		t.Fatalf("reading committed schema: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("schema/agent-report.v1.schema.json is stale — run `go run ./cmd/genschema` and commit the result")
	}
}
