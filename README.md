# SNMP Test Agent

A small, self-contained **SNMPv3 agent** for testing SNMP applications.

It serves a configurable set of OIDs over SNMPv3 and ships with a minimal web UI
(server-rendered, [htmx](https://htmx.org), no hand-written JavaScript) that shows
the configured credentials and lets you switch the value each OID returns with a
click. Each OID starts on a **random** value from its list, so every run looks a
little different.

```
┌─────────────┐   click a value    ┌──────────────┐   SNMPv3 GET    ┌──────────┐
│  Web UI     │ ─────────────────▶ │ shared state │ ◀────────────── │ your app │
│  (htmx)     │                    │  (current)   │ ──────────────▶ │ (client) │
└─────────────┘                    └──────────────┘                 └──────────┘
```

## Build

```sh
go build -o snmpsim .
```

## Run

```sh
./snmpsim -endpoint 0.0.0.0:1161 -http :8080 \
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
  simulated instance (e.g. `printer-lab-3`). Defaults to `snmpsim` so the
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
