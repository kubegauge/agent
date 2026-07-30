// schema_test.go locks the committed schema file to the Go structs (drift guard: regenerating must
// be a no-op) — the public transparency claim is "the schema IS the code".
package wire

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
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

// TestGeneratedSchemaPinsCheckStatusEnum ties the enum struct tag on CheckResult.Status to
// CheckStatuses, and proves the generator actually emits it.
//
// The platform validates every ingest against a vendored copy of this file. Until this enum was
// generated, that copy carried the constraint as a hand-applied patch, so any re-copy from here
// silently dropped it — and an unrecognized status then flowed all the way to the dashboard's
// scoring, turning one check into NaN across a tenant's entire report. Generating the constraint is
// what makes a re-copy safe.
func TestGeneratedSchemaPinsCheckStatusEnum(t *testing.T) {
	raw, err := os.ReadFile("../../schema/agent-report.v1.schema.json")
	if err != nil {
		t.Fatalf("reading committed schema: %v", err)
	}
	var doc struct {
		Defs struct {
			CheckResult struct {
				Properties struct {
					Status struct {
						Type string   `json:"type"`
						Enum []string `json:"enum"`
					} `json:"status"`
				} `json:"properties"`
			} `json:"CheckResult"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing committed schema: %v", err)
	}

	status := doc.Defs.CheckResult.Properties.Status
	if status.Type != "string" {
		t.Errorf("CheckResult.status type = %q, want string", status.Type)
	}
	if !reflect.DeepEqual(status.Enum, CheckStatuses) {
		t.Errorf("CheckResult.status enum = %v, want %v (keep the struct tag and CheckStatuses in sync)", status.Enum, CheckStatuses)
	}
}
