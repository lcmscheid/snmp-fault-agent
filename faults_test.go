package main

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

const sysDescr = "1.3.6.1.2.1.1.1.0"

// TestBaselineGet is the control: with no faults the agent must behave.
func TestBaselineGet(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newClient(t, endpoint)

	res, err := client.Get([]string{sysDescr})
	if err != nil {
		t.Fatalf("baseline GET failed: %v", err)
	}
	if len(res.Variables) != 1 {
		t.Fatalf("expected 1 varbind, got %d", len(res.Variables))
	}
	if res.Error != gosnmp.NoError {
		t.Fatalf("expected NoError, got %v", res.Error)
	}
}

// TestSemanticFaultsSurviveReauthentication is the test that matters: a
// semantically faulted response must still authenticate. If re-marshalling
// broke the digest, the client would report an authentication failure and
// never see the fault we injected — the fault would be untestable.
func TestSemanticFaultsSurviveReauthentication(t *testing.T) {
	tests := []struct {
		name  string
		fault string
		check func(t *testing.T, res *gosnmp.SnmpPacket)
	}{
		{
			name:  "tooBig",
			fault: "tooBig",
			check: func(t *testing.T, res *gosnmp.SnmpPacket) {
				if res.Error != gosnmp.TooBig {
					t.Errorf("expected TooBig, got %v", res.Error)
				}
			},
		},
		{
			name:  "genErr",
			fault: "genErr",
			check: func(t *testing.T, res *gosnmp.SnmpPacket) {
				if res.Error != gosnmp.GenErr {
					t.Errorf("expected GenErr, got %v", res.Error)
				}
			},
		},
		{
			name:  "nonIncreasingOID",
			fault: "nonIncreasingOID",
			check: func(t *testing.T, res *gosnmp.SnmpPacket) {
				if len(res.Variables) == 0 {
					t.Fatal("expected at least one varbind")
				}
				// The fault echoes the requested OID back rather than the
				// following one, which is what makes an unguarded walk loop.
				got := res.Variables[0].Name
				if got != "."+sysDescr && got != sysDescr {
					t.Errorf("expected the requested OID echoed back, got %q", got)
				}
			},
		},
	}

	endpoint, faults := startTestAgent(t)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			faults.Clear()
			if err := faults.Set(tc.fault, "on"); err != nil {
				t.Fatalf("setting fault: %v", err)
			}
			t.Cleanup(faults.Clear)

			client := newClient(t, endpoint)

			var res *gosnmp.SnmpPacket
			var err error
			if tc.fault == "nonIncreasingOID" {
				res, err = client.GetNext([]string{sysDescr})
			} else {
				res, err = client.Get([]string{sysDescr})
			}
			if err != nil {
				t.Fatalf("request failed (a digest failure here means re-marshalling "+
					"did not re-authenticate): %v", err)
			}
			tc.check(t, res)
		})
	}
}

// TestDropFault checks that a dropped response surfaces as a timeout rather
// than anything else.
func TestDropFault(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	if err := faults.Set("dropRate", "1"); err != nil {
		t.Fatalf("setting fault: %v", err)
	}
	t.Cleanup(faults.Clear)

	client := newClient(t, endpoint)
	if _, err := client.Get([]string{sysDescr}); err == nil {
		t.Fatal("expected a timeout when every response is dropped")
	}
}

// TestClearRestoresGoodBehaviour guards against a fault leaking across tests.
func TestClearRestoresGoodBehaviour(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	if err := faults.Set("tooBig", "on"); err != nil {
		t.Fatalf("setting fault: %v", err)
	}
	faults.Clear()

	client := newClient(t, endpoint)
	res, err := client.Get([]string{sysDescr})
	if err != nil {
		t.Fatalf("GET after clear failed: %v", err)
	}
	if res.Error != gosnmp.NoError {
		t.Fatalf("expected NoError after clear, got %v", res.Error)
	}
}

// TestEngineTimeOffsetDoesNotBreakTheExchange pins down what the engine-time
// fault actually does, which is less than its name suggests.
//
// GoSNMPServer v0.5.2 performs no timeliness check on incoming requests: there
// is no 150-second window and no usmStatsNotInTimeWindows report in the library
// at all. So jumping the engine clock changes what the agent reports but does
// not cause a request to be rejected. This test asserts that non-rejection, so
// that if the behaviour ever changes — because we implement reports, or because
// upstream does — it fails and forces us to revisit the fault's documentation.
func TestEngineTimeOffsetDoesNotBreakTheExchange(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	t.Cleanup(faults.Clear)

	client := newClient(t, endpoint)

	// First request performs discovery and syncs boots/time.
	if _, err := client.Get([]string{sysDescr}); err != nil {
		t.Fatalf("initial GET failed: %v", err)
	}

	// Now jump the engine well outside the 150-second window (RFC 3414 §2.2.3)
	// behind the client's back.
	if err := faults.Set("engineTimeOffsetS", "600"); err != nil {
		t.Fatalf("setting fault: %v", err)
	}

	if _, err := client.Get([]string{sysDescr}); err != nil {
		t.Fatalf("expected the exchange to survive an engine-time jump, since the "+
			"library enforces no time window; got %v. If this now fails, the "+
			"timeliness behaviour changed and the fault docs need updating.", err)
	}
}
