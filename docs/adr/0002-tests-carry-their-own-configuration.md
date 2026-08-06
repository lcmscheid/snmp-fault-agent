# Tests carry their own configuration, and the example is guarded separately

Every test used to start the agent from `examples/*.json`, which made a
user-facing document load-bearing for CI: editing the example to demonstrate
something moved the suite, and the suite in turn discouraged editing the
example. Tests now carry their configuration as JSON written out in the test
package, and the shipped example has its own guard asserting the claims the
README makes about it — every protocol name and value type, a user at each
security level, both AES key extensions genuinely exercised.

## Considered options

Test configuration could have been built as in-memory `AuthConfig` and
`ValueDef` values, skipping the loaders entirely, which `buildAgent` would
accept directly. Raw JSON was chosen instead so that the document a test depends
on is visible next to the behaviour it asserts, and so a test cannot express a
configuration the file format itself cannot.

## Consequences

- The test configuration and the shipped example are now near-identical
  documents that can drift apart. That is the point rather than a defect: the
  example is checked against its own claims, not against the test copy, so the
  two are free to diverge as each is edited for its own purpose.
- Configurations the example should never demonstrate are now testable — the
  first being an empty community, which disables v2c. An example serving nothing
  at v2c would be a poor example, so that mode had no wire coverage before.
