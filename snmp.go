package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/sirupsen/logrus"
	server "github.com/slayercat/GoSNMPServer"
)

// agentLogger returns an Info-level logger so the agent reports activity
// without the firehose of the library's default Trace level.
func agentLogger() server.ILogger {
	l := logrus.New()
	l.SetLevel(logrus.InfoLevel)
	return server.WrapLogrus(l)
}

// baseEngineBoots is the engine boots value reported when no restart is being
// simulated. Real agents start at 1 after their first boot.
const baseEngineBoots = 1

// buildAgent constructs a master agent that serves the current value of every
// OID in the store using the supplied credentials.
//
// The engine time is supplied through a hook rather than left to the library's
// default, so the faults can shift it out of the RFC 3414 §2.2.3 time window
// while the agent is running.
func buildAgent(auth *AuthConfig, store *Store, faults *Faults) (*server.MasterAgent, error) {
	engineID, err := auth.EngineIDData()
	if err != nil {
		return nil, err
	}

	oids := make([]*server.PDUValueControlItem, 0, len(store.entries))
	for _, e := range store.entries {
		oid := e.OID
		oidType, _, encErr := encodeValue(e.Type, e.Current())
		if encErr != nil {
			return nil, encErr
		}
		item := &server.PDUValueControlItem{
			OID:      oid,
			Type:     oidType,
			Document: e.Name,
			OnGet: func() (interface{}, error) {
				_, val, getErr := store.snmpValue(oid)
				if getErr != nil {
					return nil, getErr
				}
				return val, nil
			},
		}
		// A nil OnSet is how the library marks an OID read-only: it answers with
		// the readOnly error rather than calling us. That is the behaviour we
		// want for a read-only entry, so leave the hook off entirely.
		if !e.ReadOnly {
			item.OnSet = func(value interface{}) error {
				return store.SetFromSNMP(oid, value)
			}
		}
		oids = append(oids, item)
	}

	started := time.Now()

	sec := server.SecurityConfig{
		// v2c is served whenever a community is configured. The client library
		// this agent exists to test reaches v2c well before v3, so refusing it
		// would leave that whole stage without a fault-injecting target.
		SnmpV3Only:               !auth.V2CEnabled(),
		Users:                    auth.UsmUsers(),
		AuthoritativeEngineID:    server.SNMPEngineID{EngineIDData: engineID},
		AuthoritativeEngineBoots: baseEngineBoots,
		OnGetAuthoritativeEngineTime: func() uint32 {
			elapsed := time.Since(started) + faults.Snapshot().EngineTimeOffset
			if elapsed < 0 {
				return 0
			}
			return uint32(elapsed.Seconds())
		},
	}

	// One routing table serves both versions: the library keys it on the context
	// name for v3 and on the community for v1/v2c. Standard v3 clients send an
	// empty context, so "" and the community both point at this sub-agent.
	routes := []string{""}
	if auth.V2CEnabled() {
		routes = append(routes, auth.Community)
	}

	master := &server.MasterAgent{
		Logger:         agentLogger(),
		SecurityConfig: sec,
		SubAgents: []*server.SubAgent{
			{
				CommunityIDs: routes,
				OIDs:         oids,
				// Without this the library swallows a handler error: it leaves
				// the PDU marked NoError and writes the message into the varbind
				// as an octet string, so a rejected SET looks to the client like
				// a successful one that returned odd text. Marking the packet
				// turns it into the genErr a client can actually branch on.
				UserErrorMarkPacket: true,
			},
		},
	}
	return master, nil
}

// maxDatagram is the largest UDP payload we will read. RFC 3417 §3.2 requires
// agents to accept at least 484 octets and recommends 1472; we allow far more
// so an oversized request is seen and rejected rather than silently truncated.
const maxDatagram = 65535

// serveSNMP owns the UDP socket directly rather than using the library's
// ServeForever, because fault injection needs to sit between building a
// response and putting it on the wire: dropping, delaying, duplicating and
// corrupting all happen here.
//
// Requests are handled serially, matching the library's own model — MasterAgent
// is not documented as safe for concurrent use. Only the delayed send is moved
// to a goroutine, so a delay fault does not stall every other request.
func serveSNMP(endpoint string, master *server.MasterAgent, faults *Faults, auth *AuthConfig) error {
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("SNMP agent listening on udp %s", conn.LocalAddr())
	return serveConn(conn, master, faults, auth)
}

// serveConn is serveSNMP over a socket the caller owns, so the caller can close
// it to stop the loop. Binding is separated from serving because a caller that
// needs a free port — a test, for instance — has to bind before it knows which
// port it got, and asking the kernel for one, releasing it, and hoping to bind
// it again is a race.
func serveConn(conn *net.UDPConn, master *server.MasterAgent, faults *Faults, auth *AuthConfig) error {
	// NewSNMPServer would normally do this for us. Since we drive the socket
	// ourselves we must call it explicitly: it builds the community-to-subagent
	// routing map and back-links each subagent to the master. Without it every
	// request is answered with an error the client reports as an invalid
	// message.
	if err := master.ReadyForWork(); err != nil {
		return err
	}

	// counts holds the report counters this engine reports. They live with the
	// loop because the loop is the engine.
	var counts reportCounters

	buf := make([]byte, maxDatagram)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		request := make([]byte, n)
		copy(request, buf[:n])

		// ResponseForBuffer decrypts the request in place, so keep a pristine
		// copy for the semantic faults that need to read what was asked for.
		pristine := make([]byte, n)
		copy(pristine, buf[:n])

		active := faults.Snapshot()

		// The engine ID the agent answers under is the fault's when
		// engineIDChange is set. Every key derives from it (RFC 3414 §2.6), so
		// this one substitution re-localizes the whole agent: the library
		// derives per request from SecurityConfig, and our own decoding and
		// reporting go through effective.
		effective := active.EffectiveAuth(auth)
		// The error cannot fire: the loader validated the configured label and
		// Faults.Set the replacement, and EffectiveAuth serves the configured
		// identity whole rather than handing back one that does not resolve.
		data, _ := effective.EngineIDData()
		master.SecurityConfig.AuthoritativeEngineID = server.SNMPEngineID{EngineIDData: data}

		// Engine boots is a plain field rather than a hook, so a simulated
		// restart is applied just before the response is built. Safe without a
		// lock because this loop is the only writer and runs serially.
		master.SecurityConfig.AuthoritativeEngineBoots = baseEngineBoots + active.EngineBootsBump

		// The engine checks come first because a request that earns a report is
		// not answered at all: the report replaces the response rather than
		// modifying it, and the semantic faults below have no GetResponse to
		// work on.
		response, counter, err := engineReport(pristine, master, effective, &counts)
		if err != nil {
			// The request earned a report and the report could not be built.
			// RFC 3414 §3.2 discards such a message rather than processing it,
			// so answering it normally here would turn a rejection into a valid
			// response.
			log.Printf("building %s report for %s (%v); discarding the request", counter, remote, err)
			continue
		}
		reported := len(response) > 0
		if reported {
			log.Printf("REPORT %s to %s", counter, remote)
		} else {
			response, err = master.ResponseForBuffer(request)
			if err != nil {
				log.Printf("building response for %s: %v", remote, err)
			}
		}
		if len(response) == 0 {
			continue
		}

		if !reported && active.anySemantic() {
			if mutated, mErr := applySemanticFaults(response, pristine, active, effective); mErr != nil {
				log.Printf("semantic fault injection failed for %s (%v); sending unmodified", remote, mErr)
			} else if mutated != nil {
				response = mutated
			}
		}

		if active.shouldDrop() {
			log.Printf("DROPPED response to %s [faults: %s]", remote, active.Describe())
			continue
		}

		response = active.applyTransport(response)

		if active.Any() {
			log.Printf("response to %s [faults: %s]", remote, active.Describe())
		}

		send := func() {
			if _, wErr := conn.WriteToUDP(response, remote); wErr != nil {
				log.Printf("sending to %s: %v", remote, wErr)
				return
			}
			if active.Duplicate {
				if _, wErr := conn.WriteToUDP(response, remote); wErr != nil {
					log.Printf("sending duplicate to %s: %v", remote, wErr)
				}
			}
		}

		if active.Delay > 0 {
			go func(d time.Duration) {
				time.Sleep(d)
				send()
			}(active.Delay)
			continue
		}
		send()
	}
}

// applySemanticFaults decodes the response we just built, mutates it, and
// re-marshals it. Working on our own output rather than rebuilding the request
// path means the library keeps doing the awkward USM work, and re-marshalling
// re-authenticates and re-encrypts with the same keys — so the client sees a
// well-formed message that is wrong in exactly the intended way, rather than
// one that merely fails its digest check.
//
// Returns nil (and no error) when nothing needed changing.
func applySemanticFaults(response, request []byte, active FaultSet, auth *AuthConfig) ([]byte, error) {
	respPkt, err := decodePacket(response, auth)
	if err != nil {
		return nil, err
	}

	st := faultState{}
	if active.NonIncreasingOID {
		// The requested OIDs are needed to echo them back. This must be the
		// pristine request: ResponseForBuffer has already decrypted the copy it
		// was given, in place.
		reqPkt, reqErr := decodePacket(request, auth)
		if reqErr != nil {
			return nil, fmt.Errorf("decoding request for non-increasing OID fault: %w", reqErr)
		}
		for _, v := range reqPkt.Variables {
			st.requestedOIDs = append(st.requestedOIDs, v.Name)
		}
	}

	if !active.applySemantic(respPkt, st) {
		return nil, nil
	}
	return respPkt.MarshalMsg()
}

// decodePacket parses an SNMP message, using the agent's own credentials when
// the message is v3 — which is what lets us decrypt and re-encrypt our own
// traffic in order to fault it.
//
// v1/v2c carries no security parameters, so the first pass is the answer. v3
// needs a second pass with the right user's keys, and which user that is only
// becomes known once the message has been parsed far enough to read the
// cleartext msgUserName from the header. That two-pass shape is the same one
// GoSNMPServer itself uses to dispatch an incoming request.
//
// Two things are easy to get wrong. The engine ID must be present, because USM
// keys are localized to it (RFC 3414 §2.6) — without it key derivation produces
// a zero-length key. And decoding decrypts in place, so every pass gets its own
// copy of the buffer: otherwise a failed decode would leave us sending a
// half-decrypted response that the client rejects as inauthentic.
func decodePacket(msg []byte, auth *AuthConfig) (*gosnmp.SnmpPacket, error) {
	probe := gosnmp.GoSNMP{SecurityParameters: &gosnmp.UsmSecurityParameters{}}
	pkt, err := probe.SnmpDecodePacket(scratchCopy(msg))
	if pkt == nil {
		if err == nil {
			err = errors.New("message did not decode to a packet")
		}
		return nil, err
	}
	if pkt.Version != gosnmp.Version3 {
		// v1/v2c carries no security parameters, so this pass was the real
		// decode and its error is final.
		if err != nil {
			return nil, err
		}
		return pkt, nil
	}
	// For v3 the probe was always going to fail to authenticate or decrypt —
	// it had no keys. Its error is expected and says nothing, so it is dropped
	// in favour of the second pass below.

	// The first pass could not authenticate or decrypt, but it did read the
	// header far enough to say who sent it.
	username := usernameOf(pkt)
	if username == "" {
		return nil, errors.New("v3 message carries no user name")
	}
	usm, err := auth.UsmUserWithEngine(username)
	if err != nil {
		return nil, err
	}
	// Derive the localized auth and privacy keys; they are not computed on
	// construction and decryption fails with a zero-size key without this.
	if err := usm.InitSecurityKeys(); err != nil {
		return nil, fmt.Errorf("initialising security keys for %q: %w", username, err)
	}

	handle := gosnmp.GoSNMP{SecurityParameters: usm}
	return handle.SnmpDecodePacket(scratchCopy(msg))
}

// usernameOf reads the USM user name from a decoded v3 packet, returning "" if
// the message carried no USM parameters.
func usernameOf(pkt *gosnmp.SnmpPacket) string {
	usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || usm == nil {
		return ""
	}
	return usm.UserName
}

// scratchCopy returns a private copy of a message, because decoding decrypts in
// place and would otherwise corrupt the caller's buffer.
func scratchCopy(msg []byte) []byte {
	out := make([]byte, len(msg))
	copy(out, msg)
	return out
}
