# snmp-fault-agent

**An SNMP agent that misbehaves on purpose.**

The most interesting code in an SNMP client only runs when the agent it is
talking to is broken — guards against non-increasing OIDs, back-off when a
response comes back `tooBig`, recovery from truncated messages. A correct agent
never produces any of that, so testing against `snmpd` or real hardware leaves
precisely that code unexercised. This agent produces it on demand.

It serves a configurable set of OIDs over SNMPv3 and ships with a minimal web UI
(server-rendered, [htmx](https://htmx.org), no hand-written JavaScript) that shows
the configured credentials, lets you switch the value each OID returns with a
click, and lets you toggle [faults](#faults) live. Each OID starts on a **random**
value from its list, so every run looks a little different.

> Not to be confused with [snmpsim](https://github.com/etingof/snmpsim), which
> replays recorded footprints of real devices and simulates agents behaving
> *correctly*. This one is deliberately wrong.

```
┌─────────────┐   click a value    ┌──────────────┐   SNMPv3 GET    ┌──────────┐
│  Web UI     │ ── value / fault ▶ │ shared state │ ◀── SNMPv3 req ─ │ your app │
│  (htmx)     │                    │  (current)   │ ──────────────▶ │ (client) │
└─────────────┘                    └──────────────┘                 └──────────┘
```

## Build

```sh
go build -o snmpfault .
```

## Run

```sh
./snmpfault -endpoint 0.0.0.0:1161 -http :8080 \
          -auth examples/auth.json -values examples/values.json
```

Then open <http://localhost:8080> for the UI.

> Ports below 1024 (such as the standard SNMP port 161) require elevated
> privileges; the examples use 1161.

### Flags

| Flag        | Default          | Description                                   |
|-------------|------------------|-----------------------------------------------|
| `-endpoint` | `0.0.0.0:1161`   | UDP `host:port` the SNMP agent listens on     |
| `-http`     | `:8080`          | `host:port` the web UI listens on             |
| `-auth`     | `auth.json`      | path to the SNMPv3 credentials JSON file      |
| `-values`   | `values.json`    | path to the values JSON file                  |

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
| **Corrupt a byte** | One bit flipped mid-message. At v3 the digest check fails; at v2c the BER decode does. |
| **Drop rate** | A fraction of responses silently discarded. Exercises timeout and retry. |
| **Delay** | Reply held back. Exceed the client's timeout to force a retry. |
| **Truncate** | Bytes chopped off the end, producing an undecodable message. |
| **Engine time offset** | Shifts the reported engine time, so an already-synced client sees the clock jump. |
| **Engine boots bump** | Raises reported engine boots, as if the device had restarted. |

The semantic faults (`tooBig`, non-increasing OID, `genErr`) are applied by
decoding the agent's own response, mutating it, and re-marshalling — so the
message is **correctly authenticated and encrypted** and is wrong in exactly the
intended way, rather than merely failing its digest check.

> **Known limitation.** The two engine-level faults change what the agent
> *reports*, but cannot provoke a `usmStatsNotInTimeWindows` report: the
> underlying [GoSNMPServer](https://github.com/slayercat/GoSNMPServer) v0.5.2
> implements no timeliness check at all — no 150-second window (RFC 3414 §2.2.3)
> and no `usmStats` reports. Real report generation would have to be added.

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
`engineTimeOffsetS`, `engineBootsBump`.

## Tests

```sh
go test ./...
```

The tests start the agent on an ephemeral port and drive it with a real gosnmp
client. The most important one asserts that a semantically faulted response
still authenticates — if re-marshalling ever broke the digest, the client would
report an authentication failure and never see the injected fault, making the
fault useless.

## Configuration

### Credentials — `auth.json`

```json
{
  "username": "testuser",
  "authProtocol": "SHA",
  "authPassphrase": "authpassword1",
  "privProtocol": "AES",
  "privPassphrase": "privpassword1",
  "engineID": "printer-lab-3"
}
```

- `authProtocol`: `none`, `MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`
- `privProtocol`: `none`, `DES`, `AES`, `AES192`, `AES256`, `AES192C`, `AES256C`
- `engineID` *(optional)*: a human-readable **identity label** for this
  simulated instance (e.g. `printer-lab-3`). Defaults to `snmpfault` so the
  engine ID is stable and never depends on the host. Prefix with `0x` to supply
  raw hex instead (e.g. `0x01020304`).
- The security level (`noAuthNoPriv` / `authNoPriv` / `authPriv`) is inferred
  from which protocols are set.

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
is chosen at random on startup and changed from the UI.

```json
{
  "values": [
    {
      "name": "System Description",
      "oid": "1.3.6.1.2.1.1.1.0",
      "type": "string",
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

Supported `type` values: `string`, `integer`, `gauge`, `counter`, `timeticks`,
`oid`.

## Try it

With [net-snmp](http://www.net-snmp.org/) installed:

```sh
snmpget -v3 -l authPriv -u testuser \
        -a SHA -A authpassword1 -x AES -X privpassword1 \
        127.0.0.1:1161 1.3.6.1.2.1.1.1.0
```

Change the value in the web UI and run the command again — the returned value
follows the UI.
