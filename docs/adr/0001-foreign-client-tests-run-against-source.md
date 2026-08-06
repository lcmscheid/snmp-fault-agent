# Foreign-client tests run against source, not the image

A fault is only proven by a client that shares no code with the agent, so
net-snmp drives one suite here. That suite runs against an agent started from
source in the Go test binary, and the container's smoke test was reduced to
liveness plus one authenticated GET — the image is built from the same commit in
the same workflow run, so a fault that works in the Go suite but not in the
image means the Dockerfile is broken, which liveness already catches. Asserting
faults in both places would buy a duplicate check and a second place to update.

## Consequences

- Assertions are on exit codes and semantics rather than net-snmp's exact
  wording, so the unpinned `snmp` package can drift with the runner image
  without turning CI red for reasons unrelated to a change.
- `EngineTimeOffset` and `EngineBootsBump` have no foreign-client coverage and
  cannot get any: GoSNMPServer performs no timeliness check, so no Report PDU is
  ever generated and a CLI client has nothing to react to (see the caveat in
  `faults.go`). Reaching them needs support added to the library first.
- The three users configured with the Reeder key extension (`AES192C`, `AES256C`)
  are skipped rather than failed: net-snmp's `-x` offers only DES, AES, AES-192
  and AES-256, the last two using the Blumenthal extension, so there is no way
  to ask it for the Reeder variants. `TestKeyExtensionSchemesDiffer` covers the
  distinction on our side.
