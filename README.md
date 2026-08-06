# snmp-fault-agent

**An SNMP agent that misbehaves on purpose.**

The most interesting code in an SNMP client only runs when the agent it is
talking to is broken — guards against non-increasing OIDs, back-off when a
response comes back `tooBig`, recovery from truncated messages. A correct agent
never produces any of that, so testing against `snmpd` or real hardware leaves
precisely that code unexercised. This agent produces it on demand.

It serves a configurable set of OIDs over **SNMPv3 and SNMPv2c**, answers **GET,
GETNEXT, GETBULK and SET**, and serves **as many USM users as you configure** —
so a client's whole auth × privacy matrix runs against one instance instead of
one agent per combination. It ships with a minimal web UI (server-rendered,
[htmx](https://htmx.org), no hand-written JavaScript) that shows the configured
credentials, lets you switch the value each OID returns with a click, and lets
you toggle [faults](#faults) live. Each OID starts on a **random** value from its
list, so every run looks a little different.

> Not to be confused with [snmpsim](https://github.com/etingof/snmpsim), which
> replays recorded footprints of real devices and simulates agents behaving
> *correctly*. This one is deliberately wrong.

```
┌─────────────┐   click a value    ┌──────────────┐  v3 / v2c reply  ┌──────────┐
│  Web UI     │ ── value / fault ▶ │ shared state │ ◀── GET / SET ── │ your app │
│  (htmx)     │                    │  (current)   │ ───────────────▶ │ (client) │
└─────────────┘                    └──────────────┘                  └──────────┘
```

## Run it

### Container

```sh
docker run --rm -p 1161:1161/udp -p 8080:8080 ghcr.io/lcmscheid/snmp-fault-agent
```

The image carries the example configuration, so it answers immediately. Mount
your own over `/etc/snmpfault/auth.json` and `/etc/snmpfault/values.json` to
replace it:

```sh
docker run --rm -p 1161:1161/udp -p 8080:8080 \
  -v "$PWD/auth.json:/etc/snmpfault/auth.json:ro" \
  ghcr.io/lcmscheid/snmp-fault-agent
```

### From source

```sh
go build -o snmpfault .
./snmpfault -endpoint 0.0.0.0:1161 -http :8080 \
          -auth examples/auth.json -values examples/values.json
```

Then open <http://localhost:8080> for the UI.

> Ports below 1024 (such as the standard SNMP port 161) require elevated
> privileges; the examples use 1161. The container runs as a non-root user and
> so cannot bind 161 inside the container either — publish it on the host with
> `-p 161:1161/udp` if you need the standard port.

### Flags

| Flag        | Default          | Description                                   |
|-------------|------------------|-----------------------------------------------|
| `-endpoint` | `0.0.0.0:1161`   | UDP `host:port` the SNMP agent listens on     |
| `-http`     | `:8080`          | `host:port` the web UI listens on             |
| `-auth`     | `auth.json`      | path to the credentials JSON file             |
| `-values`   | `values.json`    | path to the values JSON file                  |
| `-engineid` | *(from `-auth`)* | engine ID to serve as, overriding the auth file |


## Operations

| Operation | Notes |
|---|---|
| **GET / GETNEXT / GETBULK** | Over SNMPv2c and SNMPv3. GETNEXT is what a walk is built from. |
| **SET** | Writes the value and returns it on the next read. A value not already in the OID's list is **appended as a new option and selected**, so the write shows up in the web UI. |
| **SET on a read-only OID** | Refused with `readOnly`. Mark an OID with `"readOnly": true` in `values.json`. |
| **SET with the wrong type** | Refused with `genErr`. (An RFC 3416 §4.2.5 agent would send `wrongType`; the underlying library offers no way to return it.) |

Both SNMP versions are served at once. v2c exists here because a client under
development reaches v2c long before it can speak v3, and it needs a
fault-injecting target for that whole stage.

## Faults

An SNMP client carries a lot of code that only ever runs when the agent it is
talking to is broken: guards against non-increasing OIDs, back-off when a
response comes back `tooBig`, recovery from truncated or undecodable messages.
**A correct agent never produces any of those conditions**, so testing only
against `snmpd` or real hardware leaves precisely that code unexercised.

This agent can be told to be wrong on purpose. Every fault is toggled live from
the web UI — no restart — and can be driven from a test over HTTP.

| Fault | What the client sees |
|---|---|
| **tooBig** | `tooBig` error with an empty varbind list (RFC 3416 §4.2.3). A walking client should shrink `max-repetitions` and retry. |
| **Non-increasing OID** | The requested OID echoed straight back. An unguarded walk loops forever; `snmpwalk` reports `Error: OID not increasing`. |
| **genErr** | A generic error instead of a value. |
| **Duplicate response** | Every response sent twice. The client must ignore the second copy. |
| **Corrupt a byte** | One bit flipped mid-message. Nothing usable arrives at either version and the client times out. Not for the reason you would expect at v3: in a response the size of a GET the flip lands in the USM security parameters, so net-snmp fails to parse them and discards the message before the digest is ever checked. |
| **Drop rate** | A fraction of responses silently discarded. Exercises timeout and retry. |
| **Delay** | Reply held back. Exceed the client's timeout to force a retry. |
| **Truncate** | Bytes chopped off the end, producing an undecodable message. |
| **Engine time offset** | *SNMPv3 only.* Shifts the reported engine time, so an already-synced client sees the clock jump and is answered with `usmStatsNotInTimeWindows` until it resynchronises. |
| **Engine boots bump** | *SNMPv3 only.* Raises reported engine boots, as if the device had restarted. Same effect: the client's cached engine state is stale and must be re-learned. |
| **Engine ID change** | *SNMPv3 only.* The agent answers as a different engine, as if the box had been replaced. A request naming the old engine ID is answered with an **unauthenticated** `usmStatsUnknownEngineIDs` report carrying the new one — a new engine ID invalidates every localized key too (RFC 3414 §2.6), so re-discovery alone is not enough: a client is back in only once it re-derives its keys against the new value. |

The semantic faults (`tooBig`, non-increasing OID, `genErr`) are applied by
decoding the agent's own response, mutating it, and re-marshalling — so the
message is **correctly authenticated and encrypted** and is wrong in exactly the
intended way, rather than merely failing its digest check.

The checks behind the three engine faults are this agent's own:
[GoSNMPServer](https://github.com/slayercat/GoSNMPServer) v0.5.2 implements
neither — no 150-second window (RFC 3414 §2.2.3) and no `usmStats` reports at
all. So an authenticated request whose engine boots or time fall outside the
window is answered here with a `usmStatsNotInTimeWindows` Report PDU,
authenticated at `authNoPriv` with the requesting user's key and carrying the
agent's real engine state; and one naming an engine ID that is not ours is
answered with a `usmStatsUnknownEngineIDs` report (RFC 3414 §3.2 (3)), sent
**unauthenticated**, because a client whose keys are localized to the engine ID
it named could not verify a digest made with the new one. Both are what a client
recovers from; a client that cannot is stuck at the first stale request, which
is the path these faults exist to reach.

> A client that discovers *after* a fault is set sees a consistent view and
> notices nothing — the faults invalidate cached state, so there has to be
> cached state. This is why a one-shot `snmpget` never sees the fault, only the
> ordinary time-synchronisation exchange.

### Driving faults from a test

```sh
# enable one fault
curl -X POST -d 'name=tooBig&value=on'        http://localhost:8080/faults
curl -X POST -d 'name=dropRate&value=0.5'     http://localhost:8080/faults
curl -X POST -d 'name=delayMS&value=3000'     http://localhost:8080/faults

# back to well-behaved
curl -X POST http://localhost:8080/faults/clear
```

Fault names match the UI fields: `tooBig`, `nonIncreasingOID`, `genErr`,
`duplicate`, `corruptByte`, `dropRate`, `delayMS`, `truncateBytes`,
`engineTimeOffsetS`, `engineBootsBump`, `engineIDChange` (a label or `0x`-prefixed
hex, empty to turn it off).

## Tests

```sh
go test ./...
```

The tests start the agent on an ephemeral port and drive it with a real gosnmp
client. The most important one asserts that a semantically faulted response
still authenticates, **for every configured user** — if re-marshalling ever broke
the digest, or the fault path reached for the wrong user's keys, the client would
report an authentication failure and never see the injected fault, making the
fault useless.

The foreign-client suite drives the agent with `net-snmp`, which shares no code
with it, so a fault is proven by a client reacting to it rather than by our own
client agreeing with us. Its fault tests run at **SNMPv2c and at SNMPv3
authPriv** — the engine faults excepted, since they exist only at v3 — because
authPriv is the level at which a re-marshalled response has to survive both the
digest and the decryption to reach a client's fault handling at all. Subtests
name the version they ran under, and skip when `net-snmp` is not installed —
except under CI, where a missing tool fails instead.

CI additionally builds the container image and drives the running container with
real `net-snmp` tools, so an image that starts but does not answer is never
published.

## Configuration

### Credentials — `auth.json`

```json
{
  "engineID": "printer-lab-3",
  "community": "public",
  "users": [
    {
      "username": "testuser",
      "authProtocol": "SHA",
      "authPassphrase": "authpassword1",
      "privProtocol": "AES",
      "privPassphrase": "privpassword1"
    },
    {
      "username": "sha512aes256",
      "authProtocol": "SHA512",
      "authPassphrase": "authpassword1",
      "privProtocol": "AES256",
      "privPassphrase": "privpassword1"
    },
    { "username": "noauthuser" }
  ]
}
```

- `users`: every USM user this agent serves. Listing several lets one instance
  cover a client's auth × privacy combinations. `examples/auth.json` ships
  fifteen, using every supported protocol at least once — not the full 7 × 7
  cross product, but every protocol and both key-extension schemes.
- `authProtocol`: `none`, `MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`
- `privProtocol`: `none`, `DES`, `AES`, `AES192`, `AES256`, `AES192C`, `AES256C`
  — the `C` suffix is the **Reeder** key-extension variant, which is
  incompatible with the plain Blumenthal form of the same cipher. Both are
  offered because deployed devices differ in which they expect. **3DES is not
  available**: the underlying gosnmp has no implementation of it, so testing a
  client's 3DES path needs real hardware.
- `community` *(optional)*: the SNMPv2c community. Defaults to `public`. Set it
  to `""` to serve **v3 only**.
- `engineID` *(optional)*: this agent's SNMPv3 **engine ID**, written as a
  readable label so it can name a simulated instance (e.g. `printer-lab-3`).
  Prefix with `0x` to supply raw hex instead (e.g. `0x01020304`). Defaults to
  `snmpfault` so the engine ID is stable and never depends on the host.
  **It is an input to key derivation, not just a name**: USM localizes every
  user's keys against it, so changing it changes every key. A client configured
  for the old one fails to authenticate, which looks exactly like a wrong
  passphrase. `-engineid` overrides this value, which is how the published
  container is given an identity without mounting a replacement `auth.json`:

  ```sh
  docker run --rm -p 1161:1161/udp -p 8080:8080 \
    ghcr.io/lcmscheid/snmp-fault-agent -engineid switch-7
  ```

  Arguments given to `docker run` are appended to the image's baked-in ones, and
  a flag repeated later wins — so any flag in the table above can be overridden
  this way without restating the rest. They are part of the image's entrypoint,
  so a deployment that replaces the command outright (a Kubernetes `command:`,
  a compose `entrypoint:`) inherits none of them and must supply them itself.
- The security level (`noAuthNoPriv` / `authNoPriv` / `authPriv`) is inferred
  from which protocols are set. An unknown protocol name is an **error**, not a
  silent fall back to `none` — a typo that quietly downgrades a user makes every
  authPriv request fail with nothing explaining why.

#### A trap when testing AES-192/256 key extensions

AES-192 and AES-256 need more key material than most hashes produce, so the
localized key is **extended** — by one of two mutually incompatible schemes,
Blumenthal (`AES192`/`AES256`) or Reeder (`AES192C`/`AES256C`). Both derive
`localizedKey || extension` and then truncate to the cipher's key length.

That truncation is the trap: **the extension bytes are only reached when the
auth hash is shorter than the key.** Pair `AES256C` with SHA-256 and the 32-byte
hash fills the 32-byte key on its own — the extension is discarded, and the two
schemes that are supposed to be incompatible derive *byte-identical keys*. A
client that implemented neither scheme would pass such a test.

| Hash | Bytes |   | Cipher | Key bytes |
|---|---|---|---|---|
| MD5 | 16 |   | AES | 16 |
| SHA | 20 |   | AES192 / AES192C | 24 |
| SHA224 | 28 |   | AES256 / AES256C | 32 |
| SHA256 | 32 | | | |
| SHA384 | 48 | | | |
| SHA512 | 64 | | | |

So pair the extended ciphers with **MD5 or SHA** to test the schemes at all.
`examples/auth.json` does, and `TestExampleConfigExercisesBothKeyExtensions`
fails if a future edit quietly undoes it. The long-hash pairings
(`sha384aes192`, `sha512aes256`) are kept because real devices use them, but
they prove nothing about which scheme a client implemented.

> **This agent infers the security level; a client should not.** A client that
> silently downgrades `authPriv` to `authNoPriv` has a security hole, whereas a
> test agent that accepts whatever arrives is merely convenient. The divergence
> is deliberate, and noted here so it is not mistaken for an inconsistency to be
> fixed.

> A single user may also be written with its fields at the top level, without a
> `users` array. That is the original schema and still loads.

> **About the engine ID.** The engine ID is this agent's stable unique
> identity. The underlying library always prepends the fixed prefix
> `80004fb805` (pysnmp enterprise + "octets" format), so your label rides in
> the data portion. For example `printer-lab-3` appears on the wire as
> `80004fb8057072696e7465722d6c61622d33`. The web UI shows both the label and
> this wire value — use the wire value wherever your client needs to match the
> agent's engine ID. To describe *what kind* of device this is (e.g. a
> printer), set `sysObjectID`/`sysDescr` in `values.json`.

### Values — `values.json`

A list of OIDs. Each has an array of values the agent can return; the active one
is chosen at random on startup and changed from the UI or by an SNMP SET.

```json
{
  "values": [
    {
      "name": "System Description",
      "oid": "1.3.6.1.2.1.1.1.0",
      "type": "string",
      "readOnly": true,
      "values": ["Router model A", "Router model B", "Router model C"]
    },
    {
      "name": "ifOperStatus.1",
      "oid": "1.3.6.1.2.1.2.2.1.8.1",
      "type": "integer",
      "values": ["1", "2"]
    }
  ]
}
```

- `readOnly` *(optional)*: refuse SET on this OID with the `readOnly` error.
  Without it the OID is writable. A client's SET error handling is otherwise
  unreachable without a real device that happens to expose a non-writable
  object.

Supported `type` values: `string`, `integer`, `gauge`, `counter`, `timeticks`,
`oid`.

## Try it

With [net-snmp](http://www.net-snmp.org/) installed, against the shipped example
configuration:

```sh
# SNMPv3, authPriv
snmpget -v3 -l authPriv -u testuser \
        -a SHA -A authpassword1 -x AES -X privpassword1 \
        127.0.0.1:1161 1.3.6.1.2.1.1.1.0

# SNMPv3 at the top of the range, and with the Reeder key extension
snmpget -v3 -l authPriv -u sha512aes256 \
        -a SHA-512 -A authpassword1 -x AES-256 -X privpassword1 \
        127.0.0.1:1161 1.3.6.1.2.1.1.1.0
snmpget -v3 -l authPriv -u reeder256 \
        -a SHA-256 -A authpassword1 -x AES-256-C -X privpassword1 \
        127.0.0.1:1161 1.3.6.1.2.1.1.1.0

# SNMPv2c
snmpget  -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1

# SET, then read it back
snmpset -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1.4.0 s "noc@example.com"
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1.4.0

# a read-only OID refuses the write
snmpset -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1.1.0 s nope
# Reason: (readOnly) ...
```

Change the value in the web UI and run the command again — the returned value
follows the UI.
