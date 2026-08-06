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
- `EngineTimeOffset` and `EngineBootsBump` have no foreign-client coverage: a
  CLI client is a fresh process that synchronises with whatever the agent
  reports, so it never holds the stale engine state those faults invalidate.
  What is covered foreign is the `usmStatsNotInTimeWindows` report that makes
  them recoverable — net-snmp is made to skip discovery with `-e`, which forces
  it through the report path. The same `-e` trick covers the engine ID fault,
  where it hands net-snmp the engine ID of the device that was replaced; the
  recovery it then has to perform, re-discovery and re-localization, is what a
  fresh CLI process does unaided, so that half needs no trick at all.
- The three users configured with the Reeder key extension (`AES192C`, `AES256C`)
  are skipped rather than failed: net-snmp's `-x` offers only DES, AES, AES-192
  and AES-256, the last two using the Blumenthal extension, so there is no way
  to ask it for the Reeder variants. `TestKeyExtensionSchemesDiffer` covers the
  distinction on our side.
