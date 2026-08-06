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

// craftGet builds an authenticated GET claiming whatever engine boots and time
// the caller wants. A normal client would send what it discovered; this is the
// only way to present stale values on purpose.
func craftGet(t *testing.T, auth *AuthConfig, username string, boots, engineTime uint32) []byte {
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
		MsgFlags:           gosnmp.AuthPriv | gosnmp.Reportable,
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
	pkt, err := decodePacket(buf[:n], testAuth(t))
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	return pkt
}

// assertTimelinessReport checks a reply is the RFC 3414 §3.2 (7b) answer to an
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

	usm, err := testAuth(t).UsmUserWithEngine("noauthuser")
	if err != nil {
		t.Fatalf("building USM parameters: %v", err)
	}
	pkt := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           gosnmp.NoAuthNoPriv | gosnmp.Reportable,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: usm,
		ContextEngineID:    usm.AuthoritativeEngineID,
		PDUType:            gosnmp.GetRequest,
		MsgID:              4243,
		RequestID:          2425,
		Variables:          []gosnmp.SnmpPDU{{Name: sysDescr, Type: gosnmp.Null}},
	}
	msg, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatalf("marshalling the crafted request: %v", err)
	}

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
