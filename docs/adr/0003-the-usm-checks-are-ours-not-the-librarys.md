# The USM checks are ours, not the library's

GoSNMPServer v0.5.2 performs almost none of RFC 3414 §3.2: no 150-second
timeliness window, no digest verification, no `usmStats` reports anywhere in it.
That left the two engine faults half-built — they changed what the agent
reported, but a client holding stale engine state was answered as if nothing had
happened, so the client code that recovers from a restarted or re-clocked device
stayed unreachable. That code is exactly what this project exists to reach.

The checks and their reports are therefore implemented here, in
`engine_report.go`, sitting in front of the library's response path: a v3
request that fails one is answered with a report and never processed further.
Five reports, in the order §3.2 checks them:

| Step | Report | Answers |
|---|---|---|
| (3) | `usmStatsUnknownEngineIDs` | an engine ID that is not ours |
| (4) | `usmStatsUnknownUserNames` | a user we do not serve |
| (6) | `usmStatsWrongDigests` | a digest that does not verify |
| (7a) | `usmStatsNotInTimeWindows` | engine state outside our window |
| (8) | `usmStatsDecryptionErrors` | a payload that will not decrypt |

They arrived in three batches and are one decision, not three: same gap, same
place, same reason. What the RFC makes differ is where each sits relative to
authentication at step (6), and that governs both the order they run in and the
security level each report is sent at — see the consequences below.

Discovery is the exception the list does not cover. A request naming no engine
ID at all carries no user name and no digest by design, so every check from (4)
onwards would fire on it. It is left to the library whole.

## Considered options

Fixing it upstream would put the checks where they belong and serve every user
of the library. It was not chosen because the fault agent needs the reports to
be faultable — a report goes through the same transport faults as any other
response, and is deliberately skipped by the semantic ones — and because
upstream work moves on upstream's schedule while the faults it unblocks are the
ones this repo advertises. Nothing here forecloses contributing it later.

The checks could also have run after the library built a response, discarding it
when out of window. They run before instead: building an answer to a request
that must not be answered is work whose only outcome is a chance to send it by
mistake.

## Consequences

- **A report is authenticated only from step (7) onwards.** The RFC states a
  security level for exactly one report: step (7a) requires `authNoPriv`. The
  other four are ours to choose, and the choice follows from where each sits
  relative to authentication at step (6). Steps (3), (4) and (6) all fail before
  this engine and the client are known to share a key, so
  signing their reports would mean signing with a key the client demonstrably
  does not have — it named another engine, a user we do not serve, or the wrong
  passphrase — and in the (4) case we hold no key to sign with at all. From (7)
  the digest has verified, so the client shares our key; step (8) is signed for
  that reason rather than because the RFC says so. Both carry the agent's own
  boots and time.
  A client resynchronises from those values, so a report that omitted or
  mis-stated them would be worse than none.
- **The digest is verified.** This reverses the original decision, which was to
  skip it on the grounds that neither gosnmp's `SnmpDecodePacket` nor
  GoSNMPServer verifies it either, so a check here "would only make the reports
  stricter than the value they guard". That reasoning held only while nothing
  depended on the verdict. `usmStatsWrongDigests` is exactly that dependency:
  without a verdict there is no report, and a client's wrong-password path stays
  as unreachable as the timeliness path was. It also stopped the agent answering
  requests it could not authenticate, which is behaviour no real engine has.
- **Verifying means recomputing the HMAC ourselves.** gosnmp's own check is
  unexported and reachable only through its client path, so `authentic` blanks
  the `msgAuthenticationParameters` field and recomputes the digest over the
  message — the same substitution gosnmp performs when it signs one, run
  backwards, and located the same way, by searching the message for the bytes
  that belong there. Both RFC 3414 (MD5, SHA) and RFC 7860 (the SHA-2 family)
  are an HMAC over the localized key truncated to the field's width, so one
  comparison serves every protocol the agent offers.
- **A message that will not decrypt is still readable enough to report on.** The
  keyless first decoding pass stops at the v3 header, and that header — engine
  ID, user name, engine state, digest — is what every check is made of. What it
  cannot give us is the request ID, which lives inside the encrypted payload; a
  report answering steps (4), (6) or (8) therefore echoes a request ID of zero.
  The message ID is echoed in every case, and that is the one a client matches
  its outstanding request on.
- A one-shot CLI client never sees the boots and clock faults, only the ordinary
  time-synchronisation exchange: it holds no cached state for those to
  invalidate. What it does exercise, and what the foreign-client suite asserts,
  is that the reports themselves are usable — net-snmp is made to skip discovery
  with `-e`, so the only route to a value is acting on what we sent back. The
  engine ID fault goes further: re-discovering and re-localizing is what a fresh
  CLI process does unaided, so the recovery from a replaced device is foreign
  end to end. The three credential reports need no such trick at all: a wrong
  `-A`, `-X` or `-u` is a state any CLI client can be put in.
