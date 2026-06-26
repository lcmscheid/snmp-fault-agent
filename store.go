package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"

	"github.com/gosnmp/gosnmp"
)

// Entry is a single managed OID together with its selectable values and the
// index of the value currently being served by the agent.
type Entry struct {
	Name    string
	OID     string
	Type    string
	Options []string
	current int
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
		e := &Entry{
			Name:    d.Name,
			OID:     normalizeOID(d.OID),
			Type:    d.Type,
			Options: d.Options,
			current: rng.Intn(len(d.Options)),
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
