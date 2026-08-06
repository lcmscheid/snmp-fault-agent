package main

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
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
// EngineTimeOffset and EngineBootsBump have no test here. A CLI client is a
// fresh process each time: it synchronises with whatever engine state the agent
// reports and so is never holding the stale state those faults invalidate. What
// can be shown foreign is the report that makes them recoverable at all, below.
// NewEngineID is the exception: -e lets the test choose the engine ID net-snmp
// presents, so the stale state can be handed to it, and the recovery from a
// device replacement — re-discover, re-localize, retry — is a fresh process
// doing exactly what a CLI client does anyway.

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

// exitCode reports the status a net-snmp tool exited with. A failure that was
// not an exit status at all — the tool never ran — is a broken harness rather
// than a fault, so it fails the test outright.
func exitCode(t *testing.T, err error) int {
	t.Helper()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("net-snmp did not run: %v", err)
	}
	return exit.ExitCode()
}

// v2cFlags returns the credentials and timing for a v2c invocation. Retries are
// off: against a fault that drops or delays, each retry costs another full
// timeout and proves nothing the first attempt did not.
func v2cFlags(timeout string) []string {
	return []string{"-v2c", "-c", defaultCommunity, "-t", timeout, "-r", "0"}
}

// v3Flags returns the authPriv credentials of the default example user. It
// takes a timeout to match v2cFlags, so a test can pin a fault either side of a
// client timeout under either version.
func v3Flags(timeout string) []string {
	return []string{
		"-v3", "-l", "authPriv", "-u", "testuser",
		"-a", "SHA", "-A", "authpassword1",
		"-x", "AES", "-X", "privpassword1",
		"-t", timeout, "-r", "0",
	}
}

// snmpVersions is the table the fault tests run over: one entry per version,
// each supplying net-snmp's credentials and timing. Adding a version later is
// an entry here rather than a new test.
//
// The v3 entry is authPriv because that is the level at which both the digest
// and the decryption have to survive the agent re-marshalling a faulted
// response — the claim our own client cannot check, since it derives keys with
// the same code the agent does and would agree with it even if both were wrong.
var snmpVersions = []struct {
	name  string
	flags func(timeout string) []string
}{
	{"v2c", v2cFlags},
	{"v3", v3Flags},
}

// forEachVersion runs body once per version in the table, naming the subtest
// after the version. It fails if fewer versions actually ran than the table
// declares: without that floor a table could report success having run only
// v2c, which is the one version that proves nothing about the digest.
func forEachVersion(t *testing.T, body func(t *testing.T, flags func(timeout string) []string)) {
	t.Helper()
	var ran int
	for _, v := range snmpVersions {
		t.Run(v.name, func(t *testing.T) {
			// Deferred so that it still counts a version that ran and failed,
			// which reaches here through Goexit. A skipped version is not a run
			// — counting it is what made this floor unable to fire at all.
			defer func() {
				if !t.Skipped() {
					ran++
				}
			}()
			body(t, v.flags)
		})
	}
	// Nothing ran at all is the documented no-net-snmp case, which skips rather
	// than fails; CI turns that into a failure through requireNetSNMP instead.
	// Some but not all is the case this floor exists for.
	if ran > 0 && ran < len(snmpVersions) {
		t.Fatalf("only %d of %d versions ran", ran, len(snmpVersions))
	}
}

// cleanWalk walks a root before any fault is set and returns its varbinds, so
// that a later comparison is against what this version really returns and a
// failure distinguishes a fired fault from a broken harness.
func cleanWalk(t *testing.T, flags []string, endpoint, root string) []string {
	t.Helper()
	out, err := runSNMP(t, "snmpwalk", append(flags, endpoint, root)...)
	if err != nil {
		t.Fatalf("clean walk failed: %v\n%s", err, out)
	}
	clean := varbinds(out)
	if len(clean) < 2 {
		t.Fatalf("expected the clean walk to return several varbinds, got %d:\n%s", len(clean), out)
	}
	return clean
}

// valueLine matches a varbind carrying a value: an OID, then a type token, then
// the value. Requiring the type is what separates a real varbind both from the
// diagnostics a fault provokes and from the endOfMibView marker that ends a
// GETBULK response, which is a varbind with an exception instead of a value and
// which snmpwalk does not print at all.
var valueLine = regexp.MustCompile(`^\S+ = [A-Za-z0-9-]+: `)

// varbinds keeps only the value lines of a walk, so two walks can be compared
// by what they actually returned.
func varbinds(out string) []string {
	var kept []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if valueLine.MatchString(line) {
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
		out, err := runSNMP(t, "snmpget", append(v3Flags("1"), endpoint, sysDescr)...)
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

// errStatusExit is snmpget's exit status when it decoded a response carrying an
// SNMP error-status. Anything it could not use — discarded, undecodable, never
// delivered — exits 1 instead, so the two are told apart without reading a word
// of net-snmp's diagnostics (ADR-0001).
const errStatusExit = 2

// TestNetSNMPFaultsBreakGet covers the faults whose visible effect is that a
// single GET stops working — by error-status PDU, by a message net-snmp cannot
// decode, or by nothing arriving at all. Each fault runs against every version
// in snmpVersions, and each run performs a clean GET first, so a failure here
// means the fault fired rather than the harness being broken.
//
// The two semantic faults here carry wantErrStatus, and it is the assertion that
// makes their v3 run worth its runtime: a plain "the command failed" is equally
// satisfied by net-snmp discarding the response as inauthentic, so re-marshalling
// could break the digest and this test would keep passing. Requiring net-snmp to
// have decoded an error-status says it authenticated, decrypted and read the PDU.
// The third semantic fault, non-increasing OID, is proven the same way by the
// walk test's requirement that the short walk still return a varbind.
func TestNetSNMPFaultsBreakGet(t *testing.T) {
	for _, tc := range []struct {
		fault, value  string
		wantErrStatus bool
	}{
		{fault: "tooBig", value: "on", wantErrStatus: true},
		{fault: "genErr", value: "on", wantErrStatus: true},
		{fault: "truncateBytes", value: "10"},
		{fault: "corruptByte", value: "on"},
		// 1.0 rather than an interesting-looking fraction: a statistical
		// setting here would only buy a flaky test.
		{fault: "dropRate", value: "1.0"},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			forEachVersion(t, func(t *testing.T, flags func(string) []string) {
				endpoint, faults := startTestAgent(t)

				if out, err := runSNMP(t, "snmpget", append(flags("1"), endpoint, sysDescr)...); err != nil {
					t.Fatalf("GET failed before the fault was set: %v\n%s", err, out)
				}

				setFault(t, faults, tc.fault, tc.value)

				out, err := runSNMP(t, "snmpget", append(flags("1"), endpoint, sysDescr)...)
				if err == nil {
					t.Fatalf("snmpget succeeded with %s=%s set; expected it to fail\n%s", tc.fault, tc.value, out)
				}
				// Read for every fault, not only the asserted ones: it is what
				// separates a tool that ran and failed from one that never ran.
				code := exitCode(t, err)
				if tc.wantErrStatus && code != errStatusExit {
					t.Fatalf("snmpget exited %d with %s=%s set, want %d — net-snmp never decoded an "+
						"error-status, so the faulted response did not reach it intact\n%s",
						code, tc.fault, tc.value, errStatusExit, out)
				}
			})
		})
	}
}

// TestNetSNMPNonIncreasingOIDStopsWalk is the fault this project exists for: a
// client without the guard walks forever. The assertion is that the walk stops
// early but returns something, which holds however net-snmp words its
// complaint. Requiring a varbind is what makes the v3 run mean anything: a walk
// that returned nothing would also be "fewer", so without it a re-marshalling
// bug that left every response inauthentic would pass here quietly.
func TestNetSNMPNonIncreasingOIDStopsWalk(t *testing.T) {
	forEachVersion(t, func(t *testing.T, flags func(string) []string) {
		endpoint, faults := startTestAgent(t)
		clean := cleanWalk(t, flags("1"), endpoint, sysObjects)

		setFault(t, faults, "nonIncreasingOID", "on")

		out, _ := runSNMP(t, "snmpwalk", append(flags("1"), endpoint, sysObjects)...)
		got := varbinds(out)
		if len(got) == 0 {
			t.Fatalf("the walk returned nothing, so no faulted response was accepted at all\n%s", out)
		}
		if len(got) >= len(clean) {
			t.Fatalf("walk returned %d varbinds with the fault set and %d without; expected it to stop early\n%s",
				len(got), len(clean), out)
		}
	})
}

// TestNetSNMPToleratesDuplicateResponses is the one fault whose correct outcome
// is nothing at all: a client must discard the second copy rather than
// mis-attribute it to a later request, so an unchanged walk is the pass. At v3
// the second copy authenticates as well, and still has to be discarded.
func TestNetSNMPToleratesDuplicateResponses(t *testing.T) {
	forEachVersion(t, func(t *testing.T, flags func(string) []string) {
		endpoint, faults := startTestAgent(t)
		clean := cleanWalk(t, flags("1"), endpoint, sysObjects)

		setFault(t, faults, "duplicate", "on")

		out, err := runSNMP(t, "snmpwalk", append(flags("1"), endpoint, sysObjects)...)
		if err != nil {
			t.Fatalf("walk failed with duplicate responses: %v\n%s", err, out)
		}
		if got := varbinds(out); strings.Join(got, "\n") != strings.Join(clean, "\n") {
			t.Fatalf("duplicate responses changed the walk:\nwant:\n%s\ngot:\n%s",
				strings.Join(clean, "\n"), strings.Join(got, "\n"))
		}
	})
}

// TestNetSNMPDelayTripsClientTimeout pins the delay either side of a real
// client's timeout, so the fault is shown to be the cause rather than a slow
// machine: the same GET fails under a short timeout and succeeds under a long
// one, with nothing else changed.
//
// The long timeout is generous because at v3 the delay slows the discovery
// exchange too, so the successful run pays it twice — a margin that is about
// the fault being slow, not about the machine being slow.
func TestNetSNMPDelayTripsClientTimeout(t *testing.T) {
	forEachVersion(t, func(t *testing.T, flags func(string) []string) {
		endpoint, faults := startTestAgent(t)

		if out, err := runSNMP(t, "snmpget", append(flags("1"), endpoint, sysDescr)...); err != nil {
			t.Fatalf("GET failed before the fault was set: %v\n%s", err, out)
		}

		setFault(t, faults, "delayMS", "3000")

		if out, err := runSNMP(t, "snmpget", append(flags("1"), endpoint, sysDescr)...); err == nil {
			t.Fatalf("snmpget succeeded under a 3s delay with a 1s timeout\n%s", out)
		}
		if out, err := runSNMP(t, "snmpget", append(flags("15"), endpoint, sysDescr)...); err != nil {
			t.Fatalf("snmpget failed under a 3s delay with a 15s timeout: %v\n%s", err, out)
		}
	})
}

// mib2 is a walk root wide enough to reach every type the example config
// serves, where sysObjects stops before the interface table.
const mib2 = "1.3.6.1.2.1"

// netSNMPAuth maps the agent's authentication protocol names onto net-snmp's
// -a values, which spell the SHA-2 family differently.
var netSNMPAuth = map[string]string{
	"MD5":    "MD5",
	"SHA":    "SHA",
	"SHA224": "SHA-224",
	"SHA256": "SHA-256",
	"SHA384": "SHA-384",
	"SHA512": "SHA-512",
}

// netSNMPPriv maps the agent's privacy protocol names onto net-snmp's -x
// values. The Reeder key-extension variants have no entry because net-snmp has
// no way to ask for them: -x takes DES, AES, AES-192 and AES-256, and the last
// two use the Blumenthal extension. A user configured with AES192C or AES256C
// is therefore skipped rather than failed — the limit is in the client, and
// TestKeyExtensionSchemesDiffer already covers the distinction on our side.
var netSNMPPriv = map[string]string{
	"DES":    "DES",
	"AES":    "AES",
	"AES192": "AES-192",
	"AES256": "AES-256",
}

// userFlags renders one configured user as net-snmp credential flags, reporting
// false when net-snmp cannot express that combination.
func userFlags(u UserConfig) ([]string, bool) {
	flags := []string{"-v3", "-l", u.SecurityLevel(), "-u", u.Username, "-t", "1", "-r", "0"}

	if u.AuthProtocol != "" {
		name, ok := netSNMPAuth[u.AuthProtocol]
		if !ok {
			return nil, false
		}
		flags = append(flags, "-a", name, "-A", u.AuthPassphrase)
	}
	if u.PrivProtocol != "" {
		name, ok := netSNMPPriv[u.PrivProtocol]
		if !ok {
			return nil, false
		}
		flags = append(flags, "-x", name, "-X", u.PrivPassphrase)
	}
	return flags, true
}

// TestNetSNMPUserMatrix is the foreign-client half of TestUserMatrix, and the
// half that carries the weight: every user is served with keys the agent
// derives itself, so gosnmp agreeing only shows the derivation is
// self-consistent. net-snmp implements the same key localisation independently,
// so it agreeing is the evidence that the derivation is actually right.
func TestNetSNMPUserMatrix(t *testing.T) {
	endpoint, _ := startTestAgent(t)

	auth := testAuth(t)

	var ran int
	for _, u := range auth.Users {
		t.Run(u.Username, func(t *testing.T) {
			flags, ok := userFlags(u)
			if !ok {
				t.Skipf("net-snmp cannot express %s/%s", u.AuthProtocol, u.PrivProtocol)
			}
			ran++
			if out, err := runSNMP(t, "snmpget", append(flags, endpoint, sysDescr)...); err != nil {
				t.Fatalf("GET as %s (%s) failed: %v\n%s", u.Username, u.SecurityLevel(), err, out)
			}
		})
	}

	// Without this the suite would report success if every user were skipped,
	// which is exactly what a protocol-name typo in the maps above would cause.
	if ran < 5 {
		t.Fatalf("only %d users were reachable with net-snmp; expected a real matrix", ran)
	}
}

// TestNetSNMPBulkWalk covers GETBULK, which has its own PDU shape and packs
// several varbinds into one response. A walk built on GETNEXT exercises none of
// that, so the assertion is that both routes return the same varbinds.
func TestNetSNMPBulkWalk(t *testing.T) {
	endpoint, _ := startTestAgent(t)

	want := cleanWalk(t, v2cFlags("1"), endpoint, mib2)

	out, err := runSNMP(t, "snmpbulkwalk", append(v2cFlags("1"), endpoint, mib2)...)
	if err != nil {
		t.Fatalf("bulk walk failed: %v\n%s", err, out)
	}
	if got := varbinds(out); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("GETBULK and GETNEXT disagree:\nGETNEXT:\n%s\nGETBULK:\n%s",
			strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
}

// TestNetSNMPRendersDeclaredTypes checks that the types declared in values.json
// survive the wire: a foreign decoder naming them back is the only evidence the
// encoding is right rather than merely consistent with our own decoder.
//
// These are ASN.1 type names rather than net-snmp diagnostics, so matching on
// them does not carry the version-drift risk that matching on wording would.
func TestNetSNMPRendersDeclaredTypes(t *testing.T) {
	endpoint, _ := startTestAgent(t)

	out, err := runSNMP(t, "snmpwalk", append(v2cFlags("1"), endpoint, mib2)...)
	if err != nil {
		t.Fatalf("walk failed: %v\n%s", err, out)
	}
	for _, want := range []string{"STRING:", "Timeticks:", "INTEGER:", "Counter32:"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the walk to render a %s value, got:\n%s", want, out)
		}
	}
}

// TestNetSNMPResynchronisesFromATimelinessReport is the foreign half of the
// timeliness check. Given -e, net-snmp skips discovery and sends an
// authenticated request claiming boots 0 and time 0 — outside the window by
// RFC 3414 §2.2.3 — so the only route to a value is: agent reports
// usmStatsNotInTimeWindows, client authenticates that report, learns the
// engine state from it and retries. A report that failed its digest, named the
// wrong counter or carried the wrong engine state would leave net-snmp with
// nothing to recover from, so exiting 0 with a value is the assertion.
//
// Both security levels are run because the report is sent at authNoPriv
// whatever the request was: an authPriv client accepting it is the part our own
// client library cannot independently confirm.
func TestNetSNMPResynchronisesFromATimelinessReport(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	engineID := "0x" + testAuth(t).WireEngineID()

	for _, u := range []UserConfig{
		{Username: "testuser", AuthProtocol: "SHA", AuthPassphrase: "authpassword1",
			PrivProtocol: "AES", PrivPassphrase: "privpassword1"},
		{Username: "md5user", AuthProtocol: "MD5", AuthPassphrase: "authpassword1"},
	} {
		t.Run(u.Username, func(t *testing.T) {
			flags, ok := userFlags(u)
			if !ok {
				t.Fatalf("net-snmp cannot express %s/%s", u.AuthProtocol, u.PrivProtocol)
			}
			args := append(flags, "-e", engineID, endpoint, sysDescr)
			out, err := runSNMP(t, "snmpget", args...)
			if err != nil {
				t.Fatalf("GET without discovery failed, so the report was not usable: %v\n%s", err, out)
			}
			if len(varbinds(out)) != 1 {
				t.Fatalf("expected one varbind after the resynchronisation, got:\n%s", out)
			}
		})
	}
}

// TestNetSNMPRecoversFromAnEngineIDChange is the foreign half of the
// engineIDChange fault, and it is testable for the same reason the timeliness
// report is: -e forces net-snmp past discovery, so the engine ID it presents is
// one the test chooses rather than one it just learned. That is the stale state
// a CLI client cannot otherwise hold.
//
// Three invocations, one per state a client can be in after a device is
// replaced. Presenting the old engine ID fails — with our report net-snmp names
// the engine ID as the problem instead of timing out, but the assertion is on
// exit status and varbinds rather than its wording (ADR-0001). Discovering
// afresh is the recovery the fault exists to exercise: it works only because
// every user is re-localized to the new engine ID, so a client that
// re-discovers and re-derives its keys is served normally.
func TestNetSNMPRecoversFromAnEngineIDChange(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	oldEngine := "0x" + testAuth(t).WireEngineID()
	newEngine := "0x" + (&AuthConfig{EngineID: replacementEngine}).WireEngineID()

	if err := faults.Set("engineIDChange", replacementEngine); err != nil {
		t.Fatalf("setting engineIDChange: %v", err)
	}

	// Pinned to the old engine ID, net-snmp cannot recover — -e means the user
	// chose that engine — so the failure is expected. What has to be shown is
	// that it failed on our report rather than on silence, and a non-zero exit
	// alone does not say which: a timeout exits non-zero too, and silence is
	// exactly what this agent used to answer with. Hence the generous -t and
	// the elapsed check. Timing rather than wording, so net-snmp's diagnostic
	// can be reworded without turning CI red (ADR-0001).
	t.Run("stale engine ID", func(t *testing.T) {
		const timeout = 5 * time.Second
		start := time.Now()
		out, err := runSNMP(t, "snmpget", append(v3Flags("5"), "-e", oldEngine, endpoint, sysDescr)...)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatalf("the replaced engine ID still served a value:\n%s", out)
		}
		if code := exitCode(t, err); code == 0 {
			t.Fatalf("expected a non-zero exit, got %d:\n%s", code, out)
		}
		if elapsed > timeout/2 {
			t.Fatalf("net-snmp took %s of its %s timeout, so it waited out silence rather than reading a report:\n%s",
				elapsed.Round(time.Millisecond), timeout, out)
		}
	})

	t.Run("re-discovered", func(t *testing.T) {
		out, err := runSNMP(t, "snmpget", append(v3Flags("1"), endpoint, sysDescr)...)
		if err != nil {
			t.Fatalf("a client that re-discovered could not get back in: %v\n%s", err, out)
		}
		if len(varbinds(out)) != 1 {
			t.Fatalf("expected one varbind after re-discovery, got:\n%s", out)
		}
	})

	t.Run("new engine ID", func(t *testing.T) {
		out, err := runSNMP(t, "snmpget", append(v3Flags("1"), "-e", newEngine, endpoint, sysDescr)...)
		if err != nil {
			t.Fatalf("the new engine ID was not served: %v\n%s", err, out)
		}
		if len(varbinds(out)) != 1 {
			t.Fatalf("expected one varbind under the new engine ID, got:\n%s", out)
		}
	})
}
