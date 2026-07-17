// cmd/genschema writes the wire contract artifacts: schema/agent-report.v1.schema.json (generated
// from internal/wire's structs) and schema/check-ids.json (sorted ids of every implemented check,
// vendored by the platform to guard catalog coverage).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/kubegauge/agent/internal/checks"
	"github.com/kubegauge/agent/internal/wire"
)

func main() {
	sch, err := wire.GenerateSchema()
	if err != nil {
		fmt.Fprintln(os.Stderr, "genschema:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("schema/agent-report.v1.schema.json", sch, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "genschema:", err)
		os.Exit(1)
	}

	ids := make([]string, 0, len(checks.All))
	for _, c := range checks.All {
		ids = append(ids, c.ID())
	}
	sort.Strings(ids)
	raw, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "genschema:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("schema/check-ids.json", append(raw, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "genschema:", err)
		os.Exit(1)
	}
	fmt.Println("schema/agent-report.v1.schema.json + schema/check-ids.json written")
}
