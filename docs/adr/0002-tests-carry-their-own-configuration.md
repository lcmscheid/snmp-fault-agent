# Tests carry their own configuration, and the example is guarded separately

Every test used to start the agent from `examples/*.json`, which made a
user-facing document load-bearing for CI: editing the example to demonstrate
something moved the suite, and the suite in turn discouraged editing the
example. Tests now carry their configuration as JSON written out in the test
package. The shipped example is guarded on its own terms instead, both
structurally — every protocol name and value type, a user at each security
level, both AES key extensions genuinely exercised — and on the wire, by
starting a real agent from the shipped paths and serving every configured user
over it. The example has to keep working, and only a wire test can show that.

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
- Structural checks alone would not have been enough. A file can parse, cover
  the whole matrix and still fail to serve: renaming the community keeps every
  structural assertion green while breaking every v2c client. The wire guards
  cost about a second, which is cheap for a document users run verbatim.
- The foreign-client guard is the only one that pins the *literal* credentials
  the README prints, since it passes them on a command line rather than reading
  them back out of the file under test. Editing a passphrase in the example
  without editing the README fails there and nowhere else.
