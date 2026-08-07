package main

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// syncedClient returns a v3 client that has completed discovery, plus the
// engine boots and time it learned. Crafting a request that is deliberately
// out of the window means first knowing where the window is.
func syncedClient(t *testing.T, endpoint string) (*gosnmp.GoSNMP, uint32, uint32) {
	t.Helper()
	client := newClient(t, endpoint)
	if _, err := client.Get([]string{sysDescr}); err != nil {
		t.Fatalf("initial GET failed: %v", err)
	}
	usm, ok := client.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatal("client carries no USM parameters after discovery")
	}
	return client, usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime
}

// craftGet builds an authenticated, reportable GET claiming whatever engine
// boots and time the caller wants. A normal client would send what it
// discovered; this is the only way to present stale values on purpose.
func craftGet(t *testing.T, auth *AuthConfig, username string, boots, engineTime uint32) []byte {
	t.Helper()
	return craftGetFlags(t, auth, username, gosnmp.AuthPriv|gosnmp.Reportable, boots, engineTime)
}

// craftGetFlags is craftGet with the message flags chosen by the caller, which
// is how the two things a client never varies on purpose — its security level,
// and whether it asks to be reported on — are put under test.
func craftGetFlags(t *testing.T, auth *AuthConfig, username string, flags gosnmp.SnmpV3MsgFlags, boots, engineTime uint32) []byte {
	t.Helper()
	usm, err := auth.UsmUserWithEngine(username)
	if err != nil {
		t.Fatalf("building USM parameters: %v", err)
	}
	usm.AuthoritativeEngineBoots = boots
	usm.AuthoritativeEngineTime = engineTime
	if err := usm.InitSecurityKeys(); err != nil {
		t.Fatalf("initialising security keys: %v", err)
	}

	pkt := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           flags,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: usm,
		ContextEngineID:    usm.AuthoritativeEngineID,
		PDUType:            gosnmp.GetRequest,
		MsgID:              4242,
		RequestID:          2424,
		Variables:          []gosnmp.SnmpPDU{{Name: sysDescr, Type: gosnmp.Null}},
	}
	msg, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatalf("marshalling the crafted request: %v", err)
	}
	return msg
}

// exchange sends one raw message to the agent and returns the raw reply,
// bypassing the client library so nothing recovers from a report behind the
// test's back.
func exchange(t *testing.T, endpoint string, msg []byte) *gosnmp.SnmpPacket {
	t.Helper()
	return exchangeAs(t, endpoint, msg, testAuth(t))
}

// exchangeAs is exchange with the credentials to read the reply supplied. A
// report answering a user the agent does not serve names that user, so decoding
// it needs the configuration the request was built from rather than the
// agent's.
func exchangeAs(t *testing.T, endpoint string, msg []byte, auth *AuthConfig) *gosnmp.SnmpPacket {
	t.Helper()
	conn, err := net.Dial("udp", endpoint)
	if err != nil {
		t.Fatalf("dialling the agent: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("sending the crafted request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("setting a read deadline: %v", err)
	}
	buf := make([]byte, maxDatagram)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	pkt, err := decodePacket(buf[:n], auth)
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	return pkt
}

// assertTimelinessReport checks a reply is the RFC 3414 §3.2 (7a) answer to an
// out-of-window request, and that it carries the engine state a client needs in
// order to resynchronise — a report a client cannot learn from is useless.
func assertTimelinessReport(t *testing.T, pkt *gosnmp.SnmpPacket, wantBoots uint32) {
	t.Helper()
	if pkt.PDUType != gosnmp.Report {
		t.Fatalf("expected a Report PDU, got %v", pkt.PDUType)
	}
	if len(pkt.Variables) != 1 {
		t.Fatalf("expected exactly one varbind in the report, got %d", len(pkt.Variables))
	}
	if got := pkt.Variables[0].Name; got != "."+usmStatsNotInTimeWindows {
		t.Fatalf("report carried %s, want .%s", got, usmStatsNotInTimeWindows)
	}
	usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatal("report carried no USM parameters, so a client cannot resynchronise from it")
	}
	if usm.AuthoritativeEngineBoots != wantBoots {
		t.Fatalf("report reported engine boots %d, want the agent's own %d",
			usm.AuthoritativeEngineBoots, wantBoots)
	}
}

// TestInWindowRequestIsAnswered is the guard against the timeliness check
// firing on ordinary traffic: the same crafted-request machinery, with the
// values a real client just discovered, must still get its value back.
func TestInWindowRequestIsAnswered(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	_, boots, engineTime := syncedClient(t, endpoint)

	pkt := exchange(t, endpoint, craftGet(t, testAuth(t), "testuser", boots, engineTime))
	if pkt.PDUType != gosnmp.GetResponse {
		t.Fatalf("an in-window request got %v, want a GetResponse", pkt.PDUType)
	}
}

// TestStaleEngineBootsGetsATimelinessReport covers the boots half of RFC 3414
// §2.2.3: any mismatch at all is out of window, however recent the clock.
func TestStaleEngineBootsGetsATimelinessReport(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	_, boots, engineTime := syncedClient(t, endpoint)

	pkt := exchange(t, endpoint, craftGet(t, testAuth(t), "testuser", boots-1, engineTime))
	assertTimelinessReport(t, pkt, boots)
}

// TestStaleEngineTimeGetsATimelinessReport covers the clock half: inside 150
// seconds is fine, outside it is not.
func TestStaleEngineTimeGetsATimelinessReport(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	_, boots, engineTime := syncedClient(t, endpoint)

	if pkt := exchange(t, endpoint, craftGet(t, testAuth(t), "testuser", boots, engineTime+100)); pkt.PDUType != gosnmp.GetResponse {
		t.Fatalf("a clock 100s ahead is inside the 150s window but got %v", pkt.PDUType)
	}
	pkt := exchange(t, endpoint, craftGet(t, testAuth(t), "testuser", boots, engineTime+600))
	assertTimelinessReport(t, pkt, boots)
}

// TestEngineFaultsProvokeAResync is what the two engine faults exist for. A
// client that has already synced holds engine state the fault invalidates
// behind its back; the agent must tell it so, and the exchange must survive
// once it has. Both faults are driven through the same client to show the
// recovery is not specific to one of them.
func TestEngineFaultsProvokeAResync(t *testing.T) {
	for _, tc := range []struct{ fault, value string }{
		{"engineBootsBump", "3"},
		{"engineTimeOffsetS", "600"},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			endpoint, faults := startTestAgent(t)
			client, boots, engineTime := syncedClient(t, endpoint)

			if err := faults.Set(tc.fault, tc.value); err != nil {
				t.Fatalf("setting fault: %v", err)
			}

			if _, err := client.Get([]string{sysDescr}); err != nil {
				t.Fatalf("expected the client to resynchronise from the report and retry; got %v", err)
			}

			usm, ok := client.SecurityParameters.(*gosnmp.UsmSecurityParameters)
			if !ok {
				t.Fatal("client carries no USM parameters after the retry")
			}
			if usm.AuthoritativeEngineBoots == boots && usm.AuthoritativeEngineTime <= engineTime+1 {
				t.Fatalf("client still holds boots=%d time=%d, so it never resynchronised",
					usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime)
			}
		})
	}
}

// TestNoAuthUserIsNotTimeChecked pins RFC 3414 §3.2 (7): the timeliness check
// applies to authenticated messages only. A noAuthNoPriv user claims no engine
// state, so answering it with a timeliness report would withhold values from
// traffic that was never in the window to begin with.
func TestNoAuthUserIsNotTimeChecked(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newUserClient(t, endpoint, UserConfig{Username: "noauthuser"})

	if _, err := client.Get([]string{sysDescr}); err != nil {
		t.Fatalf("a noAuthNoPriv GET failed: %v", err)
	}
}

// replacementEngine is the identity the agent takes on when engineIDChange is
// set in the tests below. It is a label rather than hex so the fault reads like
// the device swap it stands for.
const replacementEngine = "replacement-box"

// TestStaleEngineIDGetsAnUnknownEngineIDReport is the case RFC 3414 §3.2 (3)
// answers and the timeliness check cannot: the request is not out of window, it
// names an engine that no longer exists. The report must be unauthenticated —
// a client holding keys localized to the old engine ID could not verify a
// digest made with the new one — and must carry the new engine ID, since
// re-discovery is the only way back in.
func TestStaleEngineIDGetsAnUnknownEngineIDReport(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	_, boots, engineTime := syncedClient(t, endpoint)

	if err := faults.Set("engineIDChange", replacementEngine); err != nil {
		t.Fatalf("setting engineIDChange: %v", err)
	}

	// Crafted from testAuth, which still holds the original engine ID: that is
	// exactly the stale state a client keeps across a device replacement.
	pkt := exchange(t, endpoint, craftGet(t, testAuth(t), "testuser", boots, engineTime))

	if pkt.PDUType != gosnmp.Report {
		t.Fatalf("expected a Report PDU, got %v", pkt.PDUType)
	}
	if len(pkt.Variables) != 1 || pkt.Variables[0].Name != "."+usmStatsUnknownEngineIDs {
		t.Fatalf("expected one .%s varbind, got %v", usmStatsUnknownEngineIDs, pkt.Variables)
	}
	if pkt.MsgFlags&gosnmp.AuthNoPriv != 0 {
		t.Fatalf("the report was authenticated (flags %v); a client that does not know the engine ID cannot verify it", pkt.MsgFlags)
	}
	usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatal("report carried no USM parameters, so a client cannot re-discover from it")
	}
	want := (&AuthConfig{EngineID: replacementEngine}).WireEngineID()
	if got := hex.EncodeToString([]byte(usm.AuthoritativeEngineID)); got != want {
		t.Fatalf("report carried engine ID %s, want the new %s", got, want)
	}
}

// TestEngineIDChangeProvokesARelocalization is what the fault exists for, and
// it drives one already-synced client all the way through rather than starting
// a fresh one: the client holds the replaced engine ID, the agent must tell it
// so, and the exchange must survive once it has.
//
// The assertion is on the client's key, not only on its engine ID. Re-discovery
// alone leaves a client authenticating with keys localized to an engine that is
// gone (RFC 3414 §2.6), so a changed engine ID with an unchanged key would mean
// the recovery this fault claims to exercise was never exercised.
func TestEngineIDChangeProvokesARelocalization(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	client, _, _ := syncedClient(t, endpoint)

	before, ok := client.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatal("client carries no USM parameters after discovery")
	}
	wasEngine, wasKey := before.AuthoritativeEngineID, string(before.SecretKey)

	if err := faults.Set("engineIDChange", replacementEngine); err != nil {
		t.Fatalf("setting engineIDChange: %v", err)
	}

	if _, err := client.Get([]string{sysDescr}); err != nil {
		t.Fatalf("expected the client to re-discover from the report and retry; got %v", err)
	}

	after := client.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if after.AuthoritativeEngineID == wasEngine {
		t.Fatalf("client still names engine %s, so it never re-discovered",
			hex.EncodeToString([]byte(wasEngine)))
	}
	if string(after.SecretKey) == wasKey {
		t.Fatal("client kept its old key, so it re-discovered without re-localizing")
	}
}

// TestUnauthenticatedStaleEngineIDIsReported pins the order of the two checks
// against RFC 3414 §3.2: the unknown-engine-ID check is step (3) and runs
// before the message is authenticated at step (6), so a noAuthNoPriv request
// naming the replaced engine is owed the same report. Without the ordering the
// agent answers it with a value instead, and a client that cached an engine ID
// at noAuthNoPriv is never told the device was replaced.
func TestUnauthenticatedStaleEngineIDIsReported(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	if err := faults.Set("engineIDChange", replacementEngine); err != nil {
		t.Fatalf("setting engineIDChange: %v", err)
	}

	msg := craftGetFlags(t, testAuth(t), "noauthuser", gosnmp.NoAuthNoPriv|gosnmp.Reportable, 0, 0)

	reply := exchange(t, endpoint, msg)
	if reply.PDUType != gosnmp.Report {
		t.Fatalf("a noAuthNoPriv request naming the replaced engine got %v, want a Report", reply.PDUType)
	}
	if len(reply.Variables) != 1 || reply.Variables[0].Name != "."+usmStatsUnknownEngineIDs {
		t.Fatalf("expected one .%s varbind, got %v", usmStatsUnknownEngineIDs, reply.Variables)
	}
}

// TestClearingEngineIDChangeRestoresTheOriginal pins the fault as reversible
// like every other: clearing it puts the original engine ID back, so a client
// that never left is served again and one that had re-localized sees a second
// replacement.
func TestClearingEngineIDChangeRestoresTheOriginal(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	if err := faults.Set("engineIDChange", replacementEngine); err != nil {
		t.Fatalf("setting engineIDChange: %v", err)
	}
	faults.Clear()

	_, boots, engineTime := syncedClient(t, endpoint)
	pkt := exchange(t, endpoint, craftGet(t, testAuth(t), "testuser", boots, engineTime))
	if pkt.PDUType != gosnmp.GetResponse {
		t.Fatalf("the original engine ID got %v after the fault was cleared, want a GetResponse", pkt.PDUType)
	}
}

// withUser returns the test configuration with one user's credentials altered,
// which is how a request is crafted with credentials the agent will disagree
// with: the client's view of the shared secret is a separate document from the
// agent's, and only here can the two be made to differ.
//
// The user is taken from the configuration the agent is serving rather than
// restated, so a test says which *one* field it got wrong and cannot silently
// become a test of a different field when the credentials move. Renaming the
// user adds it instead of replacing it, which is how a request names a user the
// agent does not serve at all.
func withUser(t *testing.T, username string, change func(*UserConfig)) *AuthConfig {
	t.Helper()
	cfg := *testAuth(t)
	u, ok := cfg.FindUser(username)
	if !ok {
		t.Fatalf("the test configuration serves no user named %q", username)
	}
	change(&u)

	users := append([]UserConfig(nil), cfg.Users...)
	for i, existing := range users {
		if existing.Username == u.Username {
			users[i] = u
			cfg.Users = users
			return &cfg
		}
	}
	cfg.Users = append(users, u)
	return &cfg
}

// assertReport checks a reply is a Report carrying one named counter, and
// nothing else. Every credential report is asserted through here, because the
// varbind is the whole message: a client branches on which counter came back.
func assertReport(t *testing.T, pkt *gosnmp.SnmpPacket, oid string) {
	t.Helper()
	if pkt.PDUType != gosnmp.Report {
		t.Fatalf("expected a Report PDU, got %v", pkt.PDUType)
	}
	if len(pkt.Variables) != 1 || pkt.Variables[0].Name != "."+oid {
		t.Fatalf("expected one .%s varbind, got %v", oid, pkt.Variables)
	}
}

// TestWrongAuthPassphraseGetsAWrongDigestsReport is RFC 3414 §3.2 (6), and it
// is two claims at once. A client that got the passphrase wrong is told so,
// rather than left to time out and blame the network. And the request is not
// answered: its digest never checked out, so as far as this engine can tell it
// was forged, and building a GetResponse for it — even one the client will
// discard as inauthentic — is behaviour no real engine has.
//
// The report is unauthenticated because it has to be: we would sign it with the
// key the client does not have.
func TestWrongAuthPassphraseGetsAWrongDigestsReport(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	_, boots, engineTime := syncedClient(t, endpoint)

	wrong := withUser(t, "testuser", func(u *UserConfig) {
		u.AuthPassphrase = "not-the-agents-passphrase"
	})

	pkt := exchange(t, endpoint, craftGet(t, wrong, "testuser", boots, engineTime))
	assertReport(t, pkt, usmStatsWrongDigests)
	if pkt.MsgFlags&gosnmp.AuthNoPriv != 0 {
		t.Fatalf("the report was authenticated (flags %v); a client with the wrong key cannot verify it", pkt.MsgFlags)
	}
}

// TestWrongPrivPassphraseGetsADecryptionErrorReport is RFC 3414 §3.2 (8): the
// authentication passphrase was right and the privacy one was not, and saying
// so is the whole value of the report — the two failures are one timeout
// otherwise.
//
// This report is authenticated, unlike the one above, and that difference is
// the point of asserting on it: reaching step (8) means the digest verified, so
// the client holds the key to check ours.
func TestWrongPrivPassphraseGetsADecryptionErrorReport(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	_, boots, engineTime := syncedClient(t, endpoint)

	wrong := withUser(t, "testuser", func(u *UserConfig) {
		u.PrivPassphrase = "not-the-agents-passphrase"
	})

	pkt := exchange(t, endpoint, craftGet(t, wrong, "testuser", boots, engineTime))
	assertReport(t, pkt, usmStatsDecryptionErrors)
	if pkt.MsgFlags&gosnmp.AuthNoPriv == 0 {
		t.Fatalf("the report was unauthenticated (flags %v); the client's auth key was right, so it can and should check ours", pkt.MsgFlags)
	}
}

// TestUnknownUserGetsAnUnknownUserNamesReport is RFC 3414 §3.2 (4). The agent
// has no key for a user it does not serve, so it can neither check the
// request's digest nor sign its own answer — which is what makes this report
// unauthenticated, and what makes it the only thing a client mistyping -u can
// be told.
func TestUnknownUserGetsAnUnknownUserNamesReport(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	_, boots, engineTime := syncedClient(t, endpoint)

	ghost := withUser(t, "testuser", func(u *UserConfig) {
		u.Username = "nosuchuser"
	})

	pkt := exchangeAs(t, endpoint, craftGet(t, ghost, "nosuchuser", boots, engineTime), ghost)
	assertReport(t, pkt, usmStatsUnknownUserNames)
	if pkt.MsgFlags&gosnmp.AuthNoPriv != 0 {
		t.Fatalf("the report was authenticated (flags %v); the agent has no key for an unknown user", pkt.MsgFlags)
	}
	usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || usm.UserName != "nosuchuser" {
		t.Fatalf("the report did not name the user it was answering, so a client cannot tell whose request it was: %v", pkt.SecurityParameters)
	}
}

// TestDiscoveryIsNotReported guards the checks above against the one v3
// exchange that legitimately carries no engine ID, no user name and no digest.
// Every one of them would fire on a discovery request; the agent must leave it
// to the library, or no client ever gets as far as its first authenticated GET.
func TestDiscoveryIsNotReported(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newClient(t, endpoint)
	if _, err := client.Get([]string{sysDescr}); err != nil {
		t.Fatalf("a client discovering from scratch could not get a value: %v", err)
	}
}

// silence asserts the agent sends nothing back at all, which is the only
// observable difference between a request discarded and one answered.
func silence(t *testing.T, endpoint string, msg []byte) {
	t.Helper()
	conn, err := net.Dial("udp", endpoint)
	if err != nil {
		t.Fatalf("dialling the agent: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("sending the crafted request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("setting a read deadline: %v", err)
	}
	buf := make([]byte, maxDatagram)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("the agent answered a request it cannot authenticate with %d bytes", n)
	}
}

// TestAForgedRequestIsNeverAnswered pins the half of RFC 3414 §3.2 that is not
// about reports at all: a message that fails a check is *discarded*, and only
// the report answering it is conditional on the reportable flag (RFC 3412
// §6.4). A forger is under no obligation to set that flag, so a check that
// returned early on it would leave the agent answering exactly the requests it
// cannot authenticate — which is the behaviour the digest check exists to stop.
func TestAForgedRequestIsNeverAnswered(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	_, boots, engineTime := syncedClient(t, endpoint)

	wrong := withUser(t, "testuser", func(u *UserConfig) {
		u.AuthPassphrase = "not-the-agents-passphrase"
	})
	silence(t, endpoint, craftGetFlags(t, wrong, "testuser", gosnmp.AuthPriv, boots, engineTime))
}
