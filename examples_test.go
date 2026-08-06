package main

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// The example configuration is a user-facing document: it is what the container
// serves with no volume mounted, and what the README's claims are demonstrated
// against. No other test reads it any more — they carry their own configuration
// inline — so without these assertions nothing would notice it decaying.
//
// Two kinds of guard sit here. The structural ones check what the files
// contain, so an example that quietly shrinks fails. The wire ones start a real
// agent from the shipped paths and talk to it, because a file that parses and
// covers the matrix can still fail to serve — and the example is exactly what
// the container runs with no volume mounted.

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

// startExampleAgent brings up the agent from the shipped files themselves,
// rather than from the configuration the rest of the suite carries inline.
func startExampleAgent(t *testing.T) string {
	t.Helper()
	endpoint, _ := startAgentWith(t, "examples/auth.json", "examples/values.json")
	return endpoint
}

// TestExampleConfigServesEveryUser is the regression guard the structural
// checks cannot be: every credential in the shipped file has to actually
// authenticate against an agent built from that file. A protocol name the
// loader accepts but the agent cannot serve would pass every check above.
func TestExampleConfigServesEveryUser(t *testing.T) {
	endpoint := startExampleAgent(t)

	auth, err := LoadAuth("examples/auth.json")
	if err != nil {
		t.Fatalf("the shipped example must load: %v", err)
	}

	for _, u := range auth.Users {
		t.Run(u.Username, func(t *testing.T) {
			res, err := newUserClient(t, endpoint, u).Get([]string{sysDescr})
			if err != nil {
				t.Fatalf("GET as %s (%s) failed against the shipped config: %v",
					u.Username, u.SecurityLevel(), err)
			}
			if res.Error != gosnmp.NoError {
				t.Fatalf("GET as %s returned %v", u.Username, res.Error)
			}
		})
	}
}

// TestExampleConfigServesV2CAndWalk covers the rest of what the README tells a
// reader to expect from the shipped configuration: v2c answers on the default
// community, and a walk returns the values.
func TestExampleConfigServesV2CAndWalk(t *testing.T) {
	endpoint := startExampleAgent(t)
	client := newV2CClient(t, endpoint)

	res, err := client.Get([]string{sysDescr})
	if err != nil {
		t.Fatalf("v2c GET failed against the shipped config: %v", err)
	}
	if res.Error != gosnmp.NoError {
		t.Fatalf("v2c GET returned %v", res.Error)
	}

	results, err := client.WalkAll(sysObjects)
	if err != nil {
		t.Fatalf("v2c walk failed against the shipped config: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("the shipped config served no varbinds on a walk")
	}
}

// TestExampleConfigAnswersNetSNMP is the same claim the image smoke test makes,
// asserted at source level where it is cheap and fails early: the credentials
// printed in the README work verbatim from a real client.
func TestExampleConfigAnswersNetSNMP(t *testing.T) {
	endpoint := startExampleAgent(t)
	if out, err := runSNMP(t, "snmpget", append(v3Flags("1"), endpoint, sysDescr)...); err != nil {
		t.Fatalf("net-snmp GET failed against the shipped config: %v\n%s", err, out)
	}
}
