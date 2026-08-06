package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// FaultSet is the set of deliberate misbehaviours the agent can exhibit. It
// exists because a correct agent cannot exercise a client's defensive code:
// nothing well-behaved ever returns a non-increasing OID, a tooBig for a small
// response, or a truncated message. Those client paths are only reachable
// against an agent that is wrong on purpose.
//
// FaultSet is a plain value with no lock, so it can be copied freely; see
// Faults for the concurrent-access wrapper.
type FaultSet struct {
	// --- Transport level: applied to the marshalled response bytes. ---

	// DropRate drops this fraction of responses (0.0 to 1.0). Exercises the
	// client's request timeout and retry path.
	DropRate float64
	// Delay is added before the response is sent. Exercises timeout tuning
	// and, when longer than the client's timeout, its retry path.
	Delay time.Duration
	// Duplicate sends every response twice. A correct client must ignore the
	// second copy rather than mis-attributing it to a later request.
	Duplicate bool
	// TruncateBytes removes this many bytes from the end of the response,
	// producing a message that fails to decode.
	TruncateBytes int
	// CorruptByte flips one bit in the middle of the response. Neither version
	// yields a decodable message: net-snmp discards it and the request times
	// out. Not on the digest at v3, though — in a response the size of a GET
	// the midpoint falls inside the USM security parameters, so parsing them
	// fails before the digest is checked.
	CorruptByte bool

	// --- Semantic: applied to the decoded response before re-marshalling. ---

	// TooBig replaces the response with a tooBig error. Drives a client's
	// max-repetitions back-off during a walk.
	TooBig bool
	// NonIncreasingOID rewrites every response OID back to the OID that was
	// requested. A client walking without a guard against this loops forever.
	NonIncreasingOID bool
	// GenErr replaces the response with a generic error.
	GenErr bool

	// --- Engine level: applied via the agent's security configuration. ---
	//
	// These two faults invalidate the engine state a client discovered earlier,
	// which the agent then answers with a usmStatsNotInTimeWindows report — see
	// timeliness.go, which implements the check because GoSNMPServer v0.5.2 has
	// none. A client holding cached state must resynchronise from that report
	// and retry; one that does not is stuck, which is the point.

	// EngineTimeOffset is added to the reported engine time, so a client that
	// discovered earlier sees the engine's clock jump. Note that a client which
	// discovers *after* the offset is set sees a consistent view and notices
	// nothing.
	EngineTimeOffset time.Duration
	// EngineBootsBump is added to the reported engine boots, simulating a
	// device that has restarted since the client last discovered it.
	EngineBootsBump uint32

	// EngineIDChange is the identity the agent answers under while it is set, as
	// if the box had been replaced or re-provisioned. It is the third and worst
	// way of telling a client its cached engine state is stale: a new engine ID
	// invalidates every localized key too (RFC 3414 §2.6), so re-discovery
	// alone does not get a client back in — it must re-derive its keys. A
	// request naming the old engine ID is answered with the
	// usmStatsUnknownEngineIDs report of RFC 3414 §3.2 (3); see
	// unknownEngineIDReport. Users are re-localized to the new engine ID, so a
	// client that does re-discover and re-localize is served normally.
	//
	// Held as a configured label rather than resolved octets, so the same
	// parsing that reads engineID from the auth file reads it here.
	EngineIDChange string
}

// Faults guards a FaultSet for concurrent use: the SNMP goroutine reads it
// while the web UI writes it.
type Faults struct {
	mu  sync.RWMutex
	set FaultSet
}

// faultState carries the per-request information the semantic faults need.
type faultState struct {
	// requestedOIDs are the OIDs from the incoming request, in order, used by
	// NonIncreasingOID to echo them back.
	requestedOIDs []string
}

// Snapshot returns a copy of the current settings, taken under the read lock so
// callers see a consistent view across several fields.
func (f *Faults) Snapshot() FaultSet {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.set
}

// Set applies a named fault value. Names match the web UI form fields.
func (f *Faults) Set(name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	on := value == "on" || value == "true" || value == "1"

	switch name {
	case "dropRate":
		v, err := parseFloat(value, 0, 1)
		if err != nil {
			return fmt.Errorf("dropRate: %w", err)
		}
		f.set.DropRate = v
	case "delayMS":
		v, err := parseInt(value, 0, 60_000)
		if err != nil {
			return fmt.Errorf("delayMS: %w", err)
		}
		f.set.Delay = time.Duration(v) * time.Millisecond
	case "duplicate":
		f.set.Duplicate = on
	case "truncateBytes":
		v, err := parseInt(value, 0, 1024)
		if err != nil {
			return fmt.Errorf("truncateBytes: %w", err)
		}
		f.set.TruncateBytes = v
	case "corruptByte":
		f.set.CorruptByte = on
	case "tooBig":
		f.set.TooBig = on
	case "nonIncreasingOID":
		f.set.NonIncreasingOID = on
	case "genErr":
		f.set.GenErr = on
	case "engineTimeOffsetS":
		v, err := parseInt(value, -2_000_000, 2_000_000)
		if err != nil {
			return fmt.Errorf("engineTimeOffsetS: %w", err)
		}
		f.set.EngineTimeOffset = time.Duration(v) * time.Second
	case "engineIDChange":
		// Off is the empty value, so the field doubles as the switch. Validated
		// through the same path the auth file goes through, since a label that
		// resolves to nothing would leave every key derived from an empty
		// engine ID with nothing to say why authentication stopped working.
		v := strings.TrimSpace(value)
		if v == "" || v == "off" {
			f.set.EngineIDChange = ""
			break
		}
		if _, err := (AuthConfig{EngineID: v}).EngineIDData(); err != nil {
			return fmt.Errorf("engineIDChange: %w", err)
		}
		f.set.EngineIDChange = v
	case "engineBootsBump":
		v, err := parseInt(value, 0, 1_000_000)
		if err != nil {
			return fmt.Errorf("engineBootsBump: %w", err)
		}
		f.set.EngineBootsBump = uint32(v)
	default:
		return fmt.Errorf("unknown fault %q", name)
	}
	return nil
}

// Clear disables every fault, so a test can reset to well-behaved in one call.
func (f *Faults) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set = FaultSet{}
}

// Any reports whether any fault is enabled, so the normal path can skip the
// decode/re-marshal round trip entirely when nothing is configured.
func (s FaultSet) Any() bool {
	return s.DropRate > 0 || s.Delay > 0 || s.Duplicate || s.TruncateBytes > 0 ||
		s.CorruptByte || s.anySemantic() ||
		s.EngineTimeOffset != 0 || s.EngineBootsBump != 0 || s.EngineIDChange != ""
}

// anySemantic reports whether any fault requires decoding the response.
func (s FaultSet) anySemantic() bool {
	return s.TooBig || s.NonIncreasingOID || s.GenErr
}

// applySemantic mutates a decoded response packet according to the semantic
// faults. It reports whether the packet changed and must be re-marshalled.
func (s FaultSet) applySemantic(pkt *gosnmp.SnmpPacket, st faultState) bool {
	if pkt == nil {
		return false
	}
	changed := false

	if s.TooBig {
		pkt.Error = gosnmp.TooBig
		pkt.ErrorIndex = 0
		// RFC 3416 §4.2.3: on tooBig the varbind list is emptied.
		pkt.Variables = nil
		changed = true
	}

	if s.GenErr && !s.TooBig {
		pkt.Error = gosnmp.GenErr
		pkt.ErrorIndex = 1
		changed = true
	}

	// Echo each requested OID straight back, so a GETNEXT returns the OID the
	// client asked for rather than the one after it. A client that does not
	// guard against a non-increasing OID will re-request it forever.
	if s.NonIncreasingOID && len(st.requestedOIDs) > 0 && len(pkt.Variables) > 0 {
		for i := range pkt.Variables {
			if i < len(st.requestedOIDs) {
				pkt.Variables[i].Name = st.requestedOIDs[i]
			} else {
				pkt.Variables[i].Name = st.requestedOIDs[len(st.requestedOIDs)-1]
			}
		}
		changed = true
	}

	return changed
}

// applyTransport mutates the marshalled bytes, returning a new slice when it
// changes anything so the caller's buffer is never aliased.
func (s FaultSet) applyTransport(out []byte) []byte {
	if s.TruncateBytes > 0 && len(out) > 1 {
		n := s.TruncateBytes
		if n >= len(out) {
			n = len(out) - 1
		}
		out = out[:len(out)-n]
	}
	if s.CorruptByte && len(out) > 0 {
		c := make([]byte, len(out))
		copy(c, out)
		c[len(c)/2] ^= 0x01
		out = c
	}
	return out
}

// shouldDrop reports whether this response should be silently discarded. It
// uses the package-level source, which is safe for concurrent use.
func (s FaultSet) shouldDrop() bool {
	switch {
	case s.DropRate <= 0:
		return false
	case s.DropRate >= 1:
		return true
	default:
		return rand.Float64() < s.DropRate
	}
}

// Describe renders the active faults as a short human-readable list, for the UI
// and for the log line written whenever a request is deliberately mishandled.
func (s FaultSet) Describe() string {
	var parts []string
	if s.DropRate > 0 {
		parts = append(parts, fmt.Sprintf("drop %.0f%%", s.DropRate*100))
	}
	if s.Delay > 0 {
		parts = append(parts, "delay "+s.Delay.String())
	}
	if s.Duplicate {
		parts = append(parts, "duplicate")
	}
	if s.TruncateBytes > 0 {
		parts = append(parts, fmt.Sprintf("truncate %dB", s.TruncateBytes))
	}
	if s.CorruptByte {
		parts = append(parts, "corrupt")
	}
	if s.TooBig {
		parts = append(parts, "tooBig")
	}
	if s.NonIncreasingOID {
		parts = append(parts, "non-increasing OID")
	}
	if s.GenErr {
		parts = append(parts, "genErr")
	}
	if s.EngineTimeOffset != 0 {
		parts = append(parts, "engineTime "+s.EngineTimeOffset.String())
	}
	if s.EngineBootsBump != 0 {
		parts = append(parts, fmt.Sprintf("boots +%d", s.EngineBootsBump))
	}
	if s.EngineIDChange != "" {
		parts = append(parts, "engine ID "+s.EngineIDChange)
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// EffectiveAuth returns the credentials as the agent is currently presenting
// them: with the replacement engine ID when engineIDChange is set, and the
// configured ones otherwise. Everything that derives a key or names this engine
// goes through it, because the engine ID is not just a name — USM localizes
// every key to it, so serving under a new one has to re-localize all of them
// (RFC 3414 §2.6).
//
// The copy is deliberate: the loaded configuration is shared with the web UI,
// which must keep displaying the identity the agent was started with.
func (s FaultSet) EffectiveAuth(auth *AuthConfig) *AuthConfig {
	if s.EngineIDChange == "" {
		return auth
	}
	c := *auth
	c.EngineID = s.EngineIDChange
	if _, err := c.EngineIDBytes(); err != nil {
		// Unreachable: Set validates a replacement before storing it. If one
		// ever did get through, the configured identity is served whole rather
		// than half of each — the engine ID the library answers with and the
		// one our reports name have to be the same value, or a client is told
		// to re-discover an engine nobody serves.
		return auth
	}
	return &c
}

// parseFloat parses a bounded float from a form value.
func parseFloat(s string, min, max float64) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("%v is outside %v..%v", v, min, max)
	}
	return v, nil
}

// parseInt parses a bounded integer from a form value.
func parseInt(s string, min, max int) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not an integer", s)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("%d is outside %d..%d", v, min, max)
	}
	return v, nil
}
