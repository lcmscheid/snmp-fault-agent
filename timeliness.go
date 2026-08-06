package main

import (
	"fmt"

	"github.com/gosnmp/gosnmp"
	server "github.com/slayercat/GoSNMPServer"
)

// usmStatsNotInTimeWindows is the counter an authoritative engine reports when
// a request's claimed engine state is outside its window (RFC 3414 §3.2 7b).
// It is the one report a client can recover from by resynchronising, which is
// what makes the two engine faults visible rather than merely reported.
const usmStatsNotInTimeWindows = "1.3.6.1.6.3.15.1.1.2.0"

// timeWindowSeconds is the ±150 seconds of RFC 3414 §2.2.3.
const timeWindowSeconds = 150

// engineBootsMax is the boots value at which RFC 3414 §2.2.2 says an engine may
// never be trusted as authoritative again, so every authenticated request is
// out of window from then on.
const engineBootsMax = 2147483647

// timelinessReport implements the check GoSNMPServer v0.5.2 leaves out
// entirely: it returns a Report PDU when an authenticated v3 request claims
// engine state outside our window, and nil when the request is in the window or
// is not the kind of message the check applies to.
//
// The report is sent at authNoPriv, authenticated with the requesting user's
// key, and carries this agent's real boots and time — RFC 3414 §3.2 (7b). A
// report the client cannot authenticate, or one that omits the current engine
// state, tells it nothing it can act on.
//
// The rest of the request is not our business: an out-of-window message is
// discarded rather than answered, so the caller must send this instead of the
// response it would otherwise have built.
//
// The digest is not verified before reporting, which RFC 3414 §3.2 step 6 would
// have done first. That is not a gap this check can close: neither gosnmp's
// SnmpDecodePacket nor GoSNMPServer verifies it either, so a forged request
// already gets a real answer out of this agent. Adding the check here alone
// would only make the report stricter than the value it guards.
func timelinessReport(request []byte, master *server.MasterAgent, auth *AuthConfig, count uint32) ([]byte, error) {
	pkt, err := decodePacket(request, auth)
	if err != nil || pkt.Version != gosnmp.Version3 {
		// A message we cannot decode is one the library will refuse on its own
		// terms, and the check applies to v3 alone.
		return nil, nil
	}
	// RFC 3414 §3.2 (7): the check is on authenticated messages only. An
	// unauthenticated one — discovery included — never claimed engine state to
	// be wrong about.
	if pkt.MsgFlags&gosnmp.AuthNoPriv == 0 {
		return nil, nil
	}
	// RFC 3412 §6.4: a report answers only a message that asked to be reported
	// on. Reporting on anything else invites two engines to report at each
	// other for ever.
	if pkt.MsgFlags&gosnmp.Reportable == 0 {
		return nil, nil
	}
	usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || usm == nil {
		return nil, nil
	}
	// A message naming a different engine is not out of window, it is out of
	// scope: RFC 3414 §3.2 (4) answers that with usmStatsUnknownEngineIDs, a
	// report this agent does not send. Neither does the library — a client
	// presenting a stale engine ID gets nothing back and is stuck, which is the
	// gap #7 exists to close. Declined here rather than answered wrongly.
	ours, err := auth.UsmUserWithEngine(usm.UserName)
	if err != nil {
		return nil, nil
	}
	if usm.AuthoritativeEngineID != ours.AuthoritativeEngineID {
		return nil, nil
	}

	boots := master.SecurityConfig.AuthoritativeEngineBoots
	now := master.SecurityConfig.OnGetAuthoritativeEngineTime()
	if inTimeWindow(usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime, boots, now) {
		return nil, nil
	}

	reportUsm := ours
	reportUsm.AuthoritativeEngineBoots = boots
	reportUsm.AuthoritativeEngineTime = now
	// A report is authenticated but never encrypted, so drop the privacy
	// protocol before the keys are derived.
	reportUsm.PrivacyProtocol = gosnmp.NoPriv
	reportUsm.PrivacyPassphrase = ""
	if err := reportUsm.InitSecurityKeys(); err != nil {
		return nil, fmt.Errorf("initialising report keys for %q: %w", usm.UserName, err)
	}

	report := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           gosnmp.AuthNoPriv,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: reportUsm,
		ContextEngineID:    reportUsm.AuthoritativeEngineID,
		PDUType:            gosnmp.Report,
		// Both identifiers are echoed: the client matches the reply to its
		// outstanding request on the message ID, and RFC 3412 §7.1 has the
		// report carry the request ID that triggered it.
		MsgID:     pkt.MsgID,
		RequestID: pkt.RequestID,
		Variables: []gosnmp.SnmpPDU{{
			Name:  usmStatsNotInTimeWindows,
			Type:  gosnmp.Counter32,
			Value: count,
		}},
	}
	return report.MarshalMsg()
}

// inTimeWindow applies RFC 3414 §2.2.3 from the authoritative engine's side:
// the boots counter must match exactly, and the clock must be within 150
// seconds either way. A boots counter at its maximum means the engine may never
// be trusted as authoritative again.
func inTimeWindow(msgBoots, msgTime, boots, now uint32) bool {
	if boots == engineBootsMax || msgBoots != boots {
		return false
	}
	drift := int64(msgTime) - int64(now)
	if drift < 0 {
		drift = -drift
	}
	return drift <= timeWindowSeconds
}
