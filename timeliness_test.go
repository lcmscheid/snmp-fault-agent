package main

import (
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
