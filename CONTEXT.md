# snmp-fault-agent

An SNMP agent that misbehaves on purpose, so that the defensive code in an SNMP
client — the paths a correct agent can never reach — can be exercised on demand.

## Language

**Fault**:
A deliberate misbehaviour the agent can be told to exhibit. Faults are the
product; the correctly-served OIDs exist only to give a fault something to
corrupt.
_Avoid_: bug, error injection, chaos

**Transport fault**:
A fault applied to the marshalled response bytes or to whether they are sent at
all — drop, delay, duplicate, truncate, corrupt.

**Semantic fault**:
A fault applied to the decoded response before it is re-marshalled — tooBig,
non-increasing OID, genErr. The message is well-formed and wrong.

**Timeliness report**:
The `usmStatsNotInTimeWindows` Report PDU an authoritative engine returns when a
request's claimed engine boots or time are outside the RFC 3414 §2.2.3 window.
It is the only answer an engine fault provokes, and the only thing a client can
resynchronise from. Implemented here because the underlying library has no
timeliness check at all.
_Avoid_: error, rejection

**Engine fault**:
A fault applied to the agent's reported SNMPv3 engine state, such as its boot
counter or clock.

## Language — testing

**In-process client test**:
A test where gosnmp drives the agent over a real socket from inside the test
binary. Proves the agent emits what it claims to emit.
_Avoid_: unit test, integration test

**Foreign-client test**:
A test where a client sharing no code with the agent — net-snmp — drives it, and
the assertion is on that client's own behaviour. The only kind of test that can
show a fault provokes a real reaction, because the reacting code is code we did
not write.
_Avoid_: integration test, e2e test

**Example configuration**:
The credential and value documents shipped in the container and mounted over to
replace. It is a user-facing demonstration of what the agent can serve, not a
test fixture, and it is held to the claims the README makes about it.
_Avoid_: default config, test config, fixture

**Image smoke test**:
A test that the published container starts, finds its baked-in configuration,
and answers at all. Says nothing about faults.
