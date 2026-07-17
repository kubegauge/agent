# Wire contract (generated)

- `agent-report.v1.schema.json` — JSON Schema of the `AgentReport` push payload, **generated from
  the Go structs** in `internal/wire` by `cmd/genschema`. This is the definitive, versioned list
  of everything the agent ever sends out of your cluster — see
  [`docs/what-leaves-your-cluster.md`](../docs/what-leaves-your-cluster.md).
- `check-ids.json` — sorted ids of every implemented check. The KubeGauge platform vendors this
  file to guarantee its educational catalog covers each one.

Regenerate after changing the wire structs or the check registry:

```sh
go run ./cmd/genschema
```

Drift is test-enforced (`internal/wire/schema_test.go`, `internal/checks/wire_integration_test.go`).
