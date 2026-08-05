package main

import (
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

// buildAgent constructs an SNMPv3-only master agent that serves the current
// value of every OID in the store using the supplied credentials.
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
		oids = append(oids, &server.PDUValueControlItem{
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
		})
	}

	started := time.Now()

	sec := server.SecurityConfig{
		SnmpV3Only:               true,
		Users:                    []gosnmp.UsmSecurityParameters{auth.UsmUser()},
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

	master := &server.MasterAgent{
		Logger:         agentLogger(),
		SecurityConfig: sec,
		SubAgents: []*server.SubAgent{
			{
				// SNMPv3 routes by context name; standard clients send an empty
				// context, so register this sub-agent under the empty context.
				CommunityIDs: []string{""},
				OIDs:         oids,
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
	// NewSNMPServer would normally do this for us. Since we drive the socket
	// ourselves we must call it explicitly: it builds the community-to-subagent
	// routing map and back-links each subagent to the master. Without it every
	// request is answered with an error the client reports as an invalid
	// message.
	if err := master.ReadyForWork(); err != nil {
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("SNMP agent listening on udp %s", endpoint)

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

		// Engine boots is a plain field rather than a hook, so a simulated
		// restart is applied just before the response is built. Safe without a
		// lock because this loop is the only writer and runs serially.
		master.SecurityConfig.AuthoritativeEngineBoots = baseEngineBoots + active.EngineBootsBump

		response, err := master.ResponseForBuffer(request)
		if err != nil {
			log.Printf("building response for %s: %v", remote, err)
		}
		if len(response) == 0 {
			continue
		}

		if active.anySemantic() {
			if mutated, mErr := applySemanticFaults(response, pristine, active, auth); mErr != nil {
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

// decodePacket parses an SNMP message using the agent's own credentials, which
// is what lets us decrypt and re-encrypt our own v3 traffic.
//
// Two things are easy to get wrong here. The engine ID must be present, because
// USM keys are localized to it (RFC 3414 §2.6) — without it key derivation
// produces a zero-length key. And decoding decrypts in place, so the caller's
// buffer is copied first: otherwise a failed decode would leave us sending a
// half-decrypted response that the client rejects as inauthentic.
func decodePacket(msg []byte, auth *AuthConfig) (*gosnmp.SnmpPacket, error) {
	usm, err := auth.UsmUserWithEngine()
	if err != nil {
		return nil, err
	}
	// Derive the localized auth and privacy keys; they are not computed on
	// construction and decryption fails with a zero-size key without this.
	if err := usm.InitSecurityKeys(); err != nil {
		return nil, fmt.Errorf("initialising security keys: %w", err)
	}

	scratch := make([]byte, len(msg))
	copy(scratch, msg)

	handle := gosnmp.GoSNMP{}
	handle.SecurityParameters = usm
	return handle.SnmpDecodePacket(scratch)
}
