# The timeliness check is ours, not the library's

GoSNMPServer v0.5.2 performs no RFC 3414 §2.2.3 timeliness check: no 150-second
window, no `usmStats` reports anywhere in it. That left the two engine faults
half-built — they changed what the agent reported, but a client holding stale
engine state was answered as if nothing had happened, so the client code that
recovers from a restarted or re-clocked device stayed unreachable. That code is
exactly what this project exists to reach.

The check and the `usmStatsNotInTimeWindows` report are therefore implemented
here, in `timeliness.go`, sitting in front of the library's response path: an
authenticated v3 request whose claimed engine boots or time are outside the
window is answered with a report and never processed further.

The engine ID fault later arrived with the same shape and joined the same file.
The library answers a request naming an engine ID that is not its own with
nothing a client can act on, so the `usmStatsUnknownEngineIDs` report of RFC
3414 §3.2 (3) is ours too. The two checks are one decision, not two: same gap,
same place, same reason. They differ in the two ways the RFC makes them differ —
the engine ID check runs before authentication at step (6) rather than after it
at step (7), and its report is sent **unauthenticated**, since a client whose
keys are localized to the engine ID it named could not verify a digest made with
any other one.

## Considered options

Fixing it upstream would put the check where it belongs and serve every user of
the library. It was not chosen because the fault agent needs the report to be
faultable — the report goes through the same transport faults as any other
response, and is deliberately skipped by the semantic ones — and because
upstream work moves on upstream's schedule while the fault it unblocks is the
one this repo advertises. Nothing here forecloses contributing it later.

The check could also have run after the library built a response, discarding it
when out of window. It runs before instead: building an answer to a request that
must not be answered is work whose only outcome is a chance to send it by
mistake.

## Consequences

- The report is built and authenticated by us, at `authNoPriv` with the
  requesting user's key, carrying the agent's own boots and time. A client
  resynchronises from those values, so a report that omitted or mis-stated them
  would be worse than none: the client would have nothing to correct itself
  with.
- The request's digest is not verified before reporting, though RFC 3414 §3.2
  step 6 puts authentication first. Neither gosnmp's `SnmpDecodePacket` nor
  GoSNMPServer verifies it, so a forged request already gets a real answer out
  of this agent; making the report stricter than the value it guards would buy
  nothing.
- Discovery stays the library's: a request naming no engine ID at all is left
  alone, so the exchange a client opens with is answered by the code that knows
  how to answer it. Only a request naming an engine that is not here is taken.
- A one-shot CLI client never sees the boots and clock faults, only the ordinary
  time-synchronisation exchange: it holds no cached state for those to
  invalidate. What it does exercise, and what the foreign-client suite asserts,
  is that the reports themselves are usable — net-snmp is made to skip discovery
  with `-e`, so the only route to a value is acting on what we sent back. The
  engine ID fault goes further: re-discovering and re-localizing is what a fresh
  CLI process does unaided, so the recovery from a replaced device is foreign
  end to end.
