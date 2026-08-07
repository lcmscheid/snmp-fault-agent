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

**Engine report**:
Any of the five `usmStats` Report PDUs the agent returns instead of a response,
when RFC 3414 §3.2 says a v3 request must not be processed. They are not faults
and are never toggled: they are the engine being *right*, and a client's
rejection-handling code is what they exist to reach. Three of them —
the **credential reports** — say the client's credentials are wrong; two say its
cached engine state is. Implemented here because the underlying library
implements almost none of §3.2.
_Avoid_: USM error, rejection, failure response

**Timeliness report**:
The `usmStatsNotInTimeWindows` Report PDU an authoritative engine returns when a
request's claimed engine boots or time are outside the RFC 3414 §2.2.3 window.
It is what the boots and clock faults provoke, and the only thing a client can
resynchronise from. An engine ID that changed is a different question, answered
by an **unknown engine ID report**. Implemented here because the underlying
library has no timeliness check at all.
_Avoid_: error, rejection

**Unknown engine ID report**:
The `usmStatsUnknownEngineIDs` Report PDU an authoritative engine returns when a
request names an engine ID that is not its own (RFC 3414 §3.2 (3)). It is what
the engine ID fault provokes, and it is a different PDU from the timeliness
report, not a variant of it: it is sent **unauthenticated**, because a client
whose keys are localized to the engine ID it named could not verify a digest
made with any other one. Recovering from it means re-discovering *and*
re-localizing, not just resynchronising.
_Avoid_: discovery response, engine ID report

**Credential report**:
The three **engine reports** that answer a request whose credentials the agent
cannot accept: `usmStatsUnknownUserNames` (no such user, §3.2 (4)),
`usmStatsWrongDigests` (the digest does not verify, §3.2 (6)) and
`usmStatsDecryptionErrors` (the payload will not decrypt, §3.2 (8)). The first
two are sent **unauthenticated**; the third is reached only once the digest has
verified, so it is signed with a key the client shares. Their point is that a
client can tell a wrong passphrase from a dead network — without them every one
of these is a timeout — and that a request whose digest never checked out stops
being answered at all.
_Avoid_: auth failure, credential error

**Engine ID**:
The octets identifying this agent as an authoritative SNMPv3 engine. Not only a
name: USM derives every user's localized keys from it, so two agents that share
a passphrase but not an engine ID share no usable key.
_Avoid_: identity label, agent name

**Engine fault**:
A fault applied to the agent's reported SNMPv3 engine state — its boot counter,
its clock, or its engine ID.

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
