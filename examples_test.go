package main

import (
	"testing"
)

// The example configuration is a user-facing document: it is what the container
// serves with no volume mounted, and what the README's claims are demonstrated
// against. No other test reads it any more — they carry their own configuration
// inline — so without these assertions nothing would notice it decaying.
//
// These are pure unit tests: they load the files and check what they contain.
// No agent, no socket.

// TestExampleAuthCoversTheAdvertisedMatrix holds examples/auth.json to the
// README's central claim, that one instance serves a client's whole auth x
// privacy matrix. An example that quietly shrank to one user would still parse.
func TestExampleAuthCoversTheAdvertisedMatrix(t *testing.T) {
	auth, err := LoadAuth("examples/auth.json")
	if err != nil {
		t.Fatalf("the shipped example must load: %v", err)
	}

	if auth.Community == "" {
		t.Error("the example disables v2c; a client reaches v2c long before v3, " +
			"so the shipped config should answer it")
	}

	// Every name the config format accepts should appear, so the example
	// demonstrates the full vocabulary rather than a corner of it. The
	// no-auth/no-priv spellings are excluded: they are aliases for absence.
	authSeen := map[string]bool{}
	privSeen := map[string]bool{}
	var noAuthNoPriv int
	for _, u := range auth.Users {
		authSeen[protoKey(u.AuthProtocol)] = true
		privSeen[protoKey(u.PrivProtocol)] = true
		if u.SecurityLevel() == "noAuthNoPriv" {
			noAuthNoPriv++
		}
	}

	for name := range authProtocols {
		if name == "" || name == "NONE" || name == "NOAUTH" {
			continue
		}
		if !authSeen[name] {
			t.Errorf("no example user uses authProtocol %s", name)
		}
	}
	for name := range privProtocols {
		if name == "" || name == "NONE" || name == "NOPRIV" {
			continue
		}
		if !privSeen[name] {
			t.Errorf("no example user uses privProtocol %s", name)
		}
	}
	if noAuthNoPriv == 0 {
		t.Error("no example user is noAuthNoPriv, which is the level a client " +
			"reaches first")
	}
}

// TestExampleAuthExercisesBothKeyExtensions is the shipped-config half of
// TestConfiguredUsersExerciseBothKeyExtensions: pairing an extended cipher with
// a hash long enough to fill the key truncates the extension away, so a config
// can name both schemes while distinguishing neither.
func TestExampleAuthExercisesBothKeyExtensions(t *testing.T) {
	auth, err := LoadAuth("examples/auth.json")
	if err != nil {
		t.Fatalf("the shipped example must load: %v", err)
	}
	requireBothKeyExtensions(t, auth)
}

// TestExampleValuesCoverEveryType checks that the example demonstrates every
// value type the agent can serve, and both a writable and a read-only OID —
// without a writable one, nothing in the example exercises SET.
func TestExampleValuesCoverEveryType(t *testing.T) {
	defs, err := LoadValues("examples/values.json")
	if err != nil {
		t.Fatalf("the shipped example must load: %v", err)
	}

	seen := map[string]bool{}
	var writable, readOnly int
	for _, d := range defs {
		seen[d.Type] = true
		if d.ReadOnly {
			readOnly++
		} else {
			writable++
		}
	}

	for _, want := range []string{"string", "timeticks", "integer", "counter", "gauge"} {
		if !seen[want] {
			t.Errorf("no example value has type %q", want)
		}
	}
	if writable == 0 {
		t.Error("every example value is read-only, so the example never exercises SET")
	}
	if readOnly == 0 {
		t.Error("no example value is read-only, so the example never shows a SET being refused")
	}
}
