package main

import (
	"fmt"
	"math/rand"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	return NewStore([]ValueDef{
		{Name: "contact", OID: "1.3.6.1.2.1.1.4.0", Type: "string", Options: []string{"a", "b"}},
		{Name: "descr", OID: "1.3.6.1.2.1.1.1.0", Type: "string", Options: []string{"x"}, ReadOnly: true},
		{Name: "status", OID: "1.3.6.1.2.1.2.2.1.8.1", Type: "integer", Options: []string{"1", "2"}},
		{Name: "temp", OID: "1.3.6.1.4.1.9999.1.1.0", Type: "gauge", Options: []string{"20"}},
	}, rand.New(rand.NewSource(1)))
}

// TestSetFromSNMPSelectsExisting checks a write of a value already on the list
// selects it rather than duplicating it.
func TestSetFromSNMPSelectsExisting(t *testing.T) {
	s := testStore(t)
	if err := s.SetFromSNMP("1.3.6.1.2.1.1.4.0", []byte("b")); err != nil {
		t.Fatalf("SET: %v", err)
	}
	e, _ := s.Get("1.3.6.1.2.1.1.4.0")
	if e.Current() != "b" {
		t.Errorf("current = %q, want b", e.Current())
	}
	if len(e.Options) != 2 {
		t.Errorf("options = %v, want the original two", e.Options)
	}
}

// TestSetFromSNMPBoundsGrowth stops a client that writes a fresh value on every
// request from growing the option list, and the page rendering it, without end.
func TestSetFromSNMPBoundsGrowth(t *testing.T) {
	s := testStore(t)
	const oid = "1.3.6.1.2.1.1.4.0"

	for i := 0; i < maxWrittenValues*3; i++ {
		if err := s.SetFromSNMP(oid, []byte(fmt.Sprintf("value-%d", i))); err != nil {
			t.Fatalf("SET %d: %v", i, err)
		}
	}

	e, _ := s.Get(oid)
	if want := 2 + maxWrittenValues; len(e.Options) != want {
		t.Errorf("options grew to %d, want capped at %d", len(e.Options), want)
	}
	// The last write must still be what a read returns, and the configured
	// values must survive eviction.
	if got, want := e.Current(), fmt.Sprintf("value-%d", maxWrittenValues*3-1); got != want {
		t.Errorf("current = %q, want %q", got, want)
	}
	if e.Options[0] != "a" || e.Options[1] != "b" {
		t.Errorf("configured values were evicted: %v", e.Options[:2])
	}
}

// TestSetFromSNMPReadOnly guards the rule at the data rather than only at the
// one call site that currently enforces it.
func TestSetFromSNMPReadOnly(t *testing.T) {
	s := testStore(t)
	if err := s.SetFromSNMP("1.3.6.1.2.1.1.1.0", []byte("nope")); err == nil {
		t.Fatal("expected a read-only OID to refuse a SET")
	}
}

// TestStoresDoNotShareOptions catches the aliasing bug where appending to one
// store's options writes through into another store built from the same
// definitions.
func TestStoresDoNotShareOptions(t *testing.T) {
	defs := []ValueDef{
		{Name: "contact", OID: "1.3.6.1.2.1.1.4.0", Type: "string", Options: []string{"a", "b"}},
	}
	rng := rand.New(rand.NewSource(1))
	a := NewStore(defs, rng)
	b := NewStore(defs, rng)

	if err := a.SetFromSNMP("1.3.6.1.2.1.1.4.0", []byte("written")); err != nil {
		t.Fatalf("SET: %v", err)
	}

	e, _ := b.Get("1.3.6.1.2.1.1.4.0")
	if len(e.Options) != 2 {
		t.Errorf("second store saw the first store's write: %v", e.Options)
	}
	if len(defs[0].Options) != 2 {
		t.Errorf("the definitions themselves were mutated: %v", defs[0].Options)
	}
}

// TestParseSetValue covers the conversion back from the varbind's Go type,
// including the rejections that make a mistyped SET fail instead of silently
// succeeding.
func TestParseSetValue(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		value   interface{}
		want    string
		wantErr bool
	}{
		{name: "string from bytes", typ: "string", value: []byte("hi"), want: "hi"},
		{name: "string from string", typ: "string", value: "hi", want: "hi"},
		{name: "integer", typ: "integer", value: 42, want: "42"},
		{name: "negative integer", typ: "integer", value: -1, want: "-1"},
		{name: "gauge from uint", typ: "gauge", value: uint(7), want: "7"},
		{name: "counter from uint32", typ: "counter", value: uint32(7), want: "7"},
		{name: "timeticks from int", typ: "timeticks", value: 7, want: "7"},
		{name: "string into integer", typ: "integer", value: []byte("hi"), wantErr: true},
		{name: "integer into string", typ: "string", value: 42, wantErr: true},
		{name: "negative into gauge", typ: "gauge", value: -1, wantErr: true},
		{name: "overflow gauge", typ: "gauge", value: uint64(1) << 33, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSetValue(tc.typ, tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
