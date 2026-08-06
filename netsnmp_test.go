package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Foreign-client tests: net-snmp drives the agent and the assertion is on what
// net-snmp itself does. The in-process tests can show that a fault was applied;
// only a client sharing no code with the agent can show that a fault provokes a
// reaction, which is the whole claim this project makes.
//
// Assertions are on exit status, or on output compared against a clean run of
// the same command, rather than on net-snmp's exact wording: the tools are
// deliberately unpinned, so a reworded diagnostic must not turn CI red. See
// docs/adr/0001-foreign-client-tests-run-against-source.md.
//
// EngineTimeOffset and EngineBootsBump have no test here and cannot get one:
// GoSNMPServer performs no timeliness check, so no Report PDU is ever generated
// and a CLI client has nothing to react to. The caveat is in faults.go.

// requireNetSNMP is set in CI so that a failed install is a failure rather than
// a suite that skips every test and reports success.
const requireNetSNMP = "SNMPFAULT_REQUIRE_NETSNMP"

// netSNMP locates a net-snmp tool, skipping the test when it is absent so a dev
// without net-snmp installed is not blocked by it.
func netSNMP(t *testing.T, tool string) string {
	t.Helper()
	path, err := exec.LookPath(tool)
	if err != nil {
		if os.Getenv(requireNetSNMP) != "" {
			t.Fatalf("%s is not on PATH and %s is set: %v", tool, requireNetSNMP, err)
		}
		t.Skipf("%s is not on PATH; install net-snmp to run the foreign-client tests", tool)
	}
	return path
}

// runSNMP invokes a net-snmp tool and returns its combined output. The error is
// the exit status, which is what most of these tests assert on.
func runSNMP(t *testing.T, tool string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(netSNMP(t, tool), args...).CombinedOutput()
	return string(out), err
}

// v2cFlags returns the credentials and timing for a v2c invocation. Retries are
// off: against a fault that drops or delays, each retry costs another full
// timeout and proves nothing the first attempt did not.
func v2cFlags(timeout string) []string {
	return []string{"-v2c", "-c", defaultCommunity, "-t", timeout, "-r", "0"}
}

// v3Flags returns the authPriv credentials of the default example user.
func v3Flags() []string {
	return []string{
		"-v3", "-l", "authPriv", "-u", "testuser",
		"-a", "SHA", "-A", "authpassword1",
		"-x", "AES", "-X", "privpassword1",
		"-t", "1", "-r", "0",
	}
}

// varbinds keeps only the value lines of a walk, dropping the diagnostics a
// fault provokes, so a walk can be compared by what it actually returned.
func varbinds(out string) []string {
	var kept []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(line, " = ") {
			kept = append(kept, line)
		}
	}
	return kept
}

// setFault turns a fault on through the same entry point the web UI uses.
func setFault(t *testing.T, f *Faults, name, value string) {
	t.Helper()
	if err := f.Set(name, value); err != nil {
		t.Fatalf("setting fault %s=%s: %v", name, value, err)
	}
}

// TestNetSNMPGet is the interop floor: net-snmp can talk to the agent at all,
// at v3 authPriv and at v2c. Everything below it asserts on a departure from
// this baseline, so it failing first localises the cause.
func TestNetSNMPGet(t *testing.T) {
	endpoint, _ := startTestAgent(t)

	t.Run("v3", func(t *testing.T) {
		out, err := runSNMP(t, "snmpget", append(v3Flags(), endpoint, sysDescr)...)
		if err != nil {
			t.Fatalf("v3 authPriv GET failed: %v\n%s", err, out)
		}
	})

	t.Run("v2c", func(t *testing.T) {
		out, err := runSNMP(t, "snmpget", append(v2cFlags("1"), endpoint, sysDescr)...)
		if err != nil {
			t.Fatalf("v2c GET failed: %v\n%s", err, out)
		}
	})
}

// TestNetSNMPSetRoundTrip covers the write path against a foreign client, which
// encodes the value itself rather than reusing the agent's own encoder.
func TestNetSNMPSetRoundTrip(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	const want = "netsnmp@example.com"

	if out, err := runSNMP(t, "snmpset", append(v2cFlags("1"), endpoint, sysContact, "s", want)...); err != nil {
		t.Fatalf("snmpset failed: %v\n%s", err, out)
	}
	out, err := runSNMP(t, "snmpget", append(v2cFlags("1"), endpoint, sysContact)...)
	if err != nil {
		t.Fatalf("snmpget after set failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("expected the set value back, got:\n%s", out)
	}
}

// TestNetSNMPFaultsBreakGet covers the faults whose visible effect is that a
// single GET stops working — by error-status PDU, by a message net-snmp cannot
// decode, or by nothing arriving at all. Each runs a clean GET first, so a
// failure here means the fault fired rather than the harness being broken.
func TestNetSNMPFaultsBreakGet(t *testing.T) {
	for _, tc := range []struct{ fault, value string }{
		{"tooBig", "on"},
		{"genErr", "on"},
		{"truncateBytes", "10"},
		{"corruptByte", "on"},
		// 1.0 rather than an interesting-looking fraction: a statistical
		// setting here would only buy a flaky test.
		{"dropRate", "1.0"},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			endpoint, faults := startTestAgent(t)

			if out, err := runSNMP(t, "snmpget", append(v2cFlags("1"), endpoint, sysDescr)...); err != nil {
				t.Fatalf("GET failed before the fault was set: %v\n%s", err, out)
			}

			setFault(t, faults, tc.fault, tc.value)

			out, err := runSNMP(t, "snmpget", append(v2cFlags("1"), endpoint, sysDescr)...)
			if err == nil {
				t.Fatalf("snmpget succeeded with %s=%s set; expected it to fail\n%s", tc.fault, tc.value, out)
			}
		})
	}
}

// TestNetSNMPNonIncreasingOIDStopsWalk is the fault this project exists for: a
// client without the guard walks forever. The assertion is that the walk
// returns fewer varbinds than a clean one, which holds however net-snmp words
// its complaint.
func TestNetSNMPNonIncreasingOIDStopsWalk(t *testing.T) {
	endpoint, faults := startTestAgent(t)

	out, err := runSNMP(t, "snmpwalk", append(v2cFlags("1"), endpoint, sysObjects)...)
	if err != nil {
		t.Fatalf("clean walk failed: %v\n%s", err, out)
	}
	clean := varbinds(out)
	if len(clean) < 2 {
		t.Fatalf("expected the clean walk to return several varbinds, got %d:\n%s", len(clean), out)
	}

	setFault(t, faults, "nonIncreasingOID", "on")

	out, _ = runSNMP(t, "snmpwalk", append(v2cFlags("1"), endpoint, sysObjects)...)
	if got := varbinds(out); len(got) >= len(clean) {
		t.Fatalf("walk returned %d varbinds with the fault set and %d without; expected it to stop early\n%s",
			len(got), len(clean), out)
	}
}

// TestNetSNMPToleratesDuplicateResponses is the one fault whose correct outcome
// is nothing at all: a client must discard the second copy rather than
// mis-attribute it to a later request, so an unchanged walk is the pass.
func TestNetSNMPToleratesDuplicateResponses(t *testing.T) {
	endpoint, faults := startTestAgent(t)

	out, err := runSNMP(t, "snmpwalk", append(v2cFlags("1"), endpoint, sysObjects)...)
	if err != nil {
		t.Fatalf("clean walk failed: %v\n%s", err, out)
	}
	clean := varbinds(out)
	if len(clean) < 2 {
		t.Fatalf("expected the clean walk to return several varbinds, got %d:\n%s", len(clean), out)
	}

	setFault(t, faults, "duplicate", "on")

	out, err = runSNMP(t, "snmpwalk", append(v2cFlags("1"), endpoint, sysObjects)...)
	if err != nil {
		t.Fatalf("walk failed with duplicate responses: %v\n%s", err, out)
	}
	if got := varbinds(out); strings.Join(got, "\n") != strings.Join(clean, "\n") {
		t.Fatalf("duplicate responses changed the walk:\nwant:\n%s\ngot:\n%s",
			strings.Join(clean, "\n"), strings.Join(got, "\n"))
	}
}

// TestNetSNMPDelayTripsClientTimeout pins the delay either side of a real
// client's timeout, so the fault is shown to be the cause rather than a slow
// machine: the same GET fails under a short timeout and succeeds under a long
// one, with nothing else changed.
func TestNetSNMPDelayTripsClientTimeout(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	setFault(t, faults, "delayMS", "3000")

	if out, err := runSNMP(t, "snmpget", append(v2cFlags("1"), endpoint, sysDescr)...); err == nil {
		t.Fatalf("snmpget succeeded under a 3s delay with a 1s timeout\n%s", out)
	}
	if out, err := runSNMP(t, "snmpget", append(v2cFlags("8"), endpoint, sysDescr)...); err != nil {
		t.Fatalf("snmpget failed under a 3s delay with an 8s timeout: %v\n%s", err, out)
	}
}
