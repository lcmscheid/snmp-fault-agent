package main

import (
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"sync"

	"github.com/gosnmp/gosnmp"
)

// Entry is a single managed OID together with its selectable values and the
// index of the value currently being served by the agent.
type Entry struct {
	Name     string
	OID      string
	Type     string
	Options  []string
	ReadOnly bool
	current  int
	// configured is how many of Options came from the config file. Anything
	// past it was written over SNMP and may be evicted.
	configured int
}

// Current returns the value string currently served for this entry.
func (e Entry) Current() string { return e.Options[e.current] }

// CurrentIndex returns the index of the currently selected value.
func (e Entry) CurrentIndex() int { return e.current }

// Store is the thread-safe shared state between the SNMP agent and the web UI.
type Store struct {
	mu      sync.RWMutex
	entries []*Entry
	byOID   map[string]*Entry
}

// NewStore builds a store from the value definitions, selecting a random
// starting value for each OID.
func NewStore(defs []ValueDef, rng *rand.Rand) *Store {
	s := &Store{byOID: make(map[string]*Entry)}
	for _, d := range defs {
		// Copy rather than alias the config's slice: a SET appends to Options,
		// and appending to an alias can write through into the caller's backing
		// array, so two stores built from the same definitions would see each
		// other's writes.
		options := append([]string(nil), d.Options...)

		e := &Entry{
			Name:     d.Name,
			OID:      normalizeOID(d.OID),
			Type:     d.Type,
			Options:  options,
			ReadOnly: d.ReadOnly,
			current:  rng.Intn(len(options)),

			configured: len(options),
		}
		s.entries = append(s.entries, e)
		s.byOID[e.OID] = e
	}
	return s
}

// Entries returns a snapshot copy of the entries for rendering.
func (s *Store) Entries() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, len(s.entries))
	for i, e := range s.entries {
		out[i] = *e
	}
	return out
}

// Get returns a snapshot of a single entry by OID.
func (s *Store) Get(oid string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byOID[normalizeOID(oid)]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Set selects the value at index for the given OID.
func (s *Store) Set(oid string, index int) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byOID[normalizeOID(oid)]
	if !ok {
		return Entry{}, fmt.Errorf("unknown oid %q", oid)
	}
	if index < 0 || index >= len(e.Options) {
		return Entry{}, fmt.Errorf("index %d out of range for oid %q", index, oid)
	}
	e.current = index
	return *e, nil
}

// SetFromSNMP applies a value received in a SET request.
//
// The store models each OID as a fixed list of selectable values, but a SET
// carries an arbitrary one. Rather than reject anything not already on the
// list, an unseen value is appended and selected — so a SET is visible in the
// web UI as a new option, and a subsequent GET returns what was written. That
// round trip is the whole point of supporting SET in a test agent.
func (s *Store) SetFromSNMP(oid string, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.byOID[normalizeOID(oid)]
	if !ok {
		return fmt.Errorf("unknown oid %q", oid)
	}
	// The web UI may change a read-only value — it is the operator, not a
	// client — but SNMP may not. buildAgent normally prevents this by leaving
	// OnSet nil so the library answers readOnly itself; the check stands so the
	// rule lives with the data rather than only at the one call site.
	if e.ReadOnly {
		return fmt.Errorf("oid %q is read-only", oid)
	}

	raw, err := parseSetValue(e.Type, value)
	if err != nil {
		return fmt.Errorf("oid %q: %w", oid, err)
	}

	for i, opt := range e.Options {
		if opt == raw {
			e.current = i
			return nil
		}
	}

	// A client writing a fresh value on every request would otherwise grow this
	// list — and the page rendering it — without limit. Values written over SNMP
	// are kept to a bounded window, oldest first out; the values from the config
	// file are never evicted, so the UI keeps offering what it started with.
	e.Options = append(e.Options, raw)
	if written := len(e.Options) - e.configured; written > maxWrittenValues {
		e.Options = append(e.Options[:e.configured], e.Options[e.configured+written-maxWrittenValues:]...)
	}
	e.current = len(e.Options) - 1
	return nil
}

// maxWrittenValues bounds how many SET-written values an OID accumulates beyond
// the ones it was configured with.
const maxWrittenValues = 16

// parseSetValue converts the Go value carried by a SET varbind into the string
// form the store holds, rejecting a value whose type does not match the OID.
//
// The rejection matters: a client that writes an OctetString to an Integer OID
// should see the SET fail, and against a permissive agent it would silently
// succeed. GoSNMPServer maps a handler error to genErr rather than the wrongType
// an RFC 3416 §4.2.5 agent would send, which is the closest signal available
// without patching the library.
func parseSetValue(typ string, value interface{}) (string, error) {
	switch typeName(typ) {
	case "string":
		switch v := value.(type) {
		case []byte:
			return string(v), nil
		case string:
			return v, nil
		}
	case "oid":
		if v, ok := value.(string); ok {
			return v, nil
		}
	case "integer":
		if v, ok := value.(int); ok {
			return strconv.Itoa(v), nil
		}
	case "gauge", "counter", "timeticks":
		// gosnmp decodes the three unsigned types into whichever of these widths
		// the value fits, so accept them all and range-check the result.
		var n uint64
		switch v := value.(type) {
		case uint:
			n = uint64(v)
		case uint32:
			n = uint64(v)
		case uint64:
			n = v
		case int:
			if v < 0 {
				return "", fmt.Errorf("%d is negative, but the OID is unsigned", v)
			}
			n = uint64(v)
		default:
			return "", fmt.Errorf("expected an unsigned value for a %s OID, got %T", typeName(typ), value)
		}
		if n > math.MaxUint32 {
			return "", fmt.Errorf("%d does not fit in the 32 bits a %s carries", n, typeName(typ))
		}
		return strconv.FormatUint(n, 10), nil
	}
	return "", fmt.Errorf("expected a %s value, got %T", typeName(typ), value)
}

// snmpValue converts the currently selected value into the wire type and Go
// value expected by the SNMP server for this entry.
func (s *Store) snmpValue(oid string) (gosnmp.Asn1BER, interface{}, error) {
	e, ok := s.Get(oid)
	if !ok {
		return 0, nil, fmt.Errorf("unknown oid %q", oid)
	}
	return encodeValue(e.Type, e.Current())
}

// encodeValue maps a textual value + type name to an SNMP ASN.1 type/value pair.
func encodeValue(typ, raw string) (gosnmp.Asn1BER, interface{}, error) {
	switch typeName(typ) {
	case "string":
		return gosnmp.OctetString, raw, nil
	case "oid":
		return gosnmp.ObjectIdentifier, raw, nil
	case "integer":
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, nil, fmt.Errorf("value %q is not an integer: %w", raw, err)
		}
		return gosnmp.Integer, n, nil
	case "gauge":
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("value %q is not a gauge: %w", raw, err)
		}
		return gosnmp.Gauge32, uint(n), nil
	case "counter":
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("value %q is not a counter: %w", raw, err)
		}
		return gosnmp.Counter32, uint(n), nil
	case "timeticks":
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("value %q is not timeticks: %w", raw, err)
		}
		return gosnmp.TimeTicks, uint32(n), nil
	default:
		return gosnmp.OctetString, raw, nil
	}
}

func typeName(t string) string {
	switch t {
	case "", "str", "string", "octet", "octetstring":
		return "string"
	case "int", "integer", "int32":
		return "integer"
	case "gauge", "gauge32", "unsigned":
		return "gauge"
	case "counter", "counter32":
		return "counter"
	case "timeticks", "ticks":
		return "timeticks"
	case "oid", "objectidentifier":
		return "oid"
	default:
		return "string"
	}
}

// normalizeOID ensures OIDs always start with a leading dot, matching the form
// used internally by the SNMP server.
func normalizeOID(oid string) string {
	if oid == "" || oid[0] == '.' {
		return oid
	}
	return "." + oid
}
