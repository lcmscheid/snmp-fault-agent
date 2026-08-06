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

// usmStatsUnknownEngineIDs is the counter an authoritative engine reports when
// a request names an engine ID that is not its own (RFC 3414 §3.2 (3)). It is a
// different answer to a different question: not "your engine state is stale"
// but "the engine you are talking to is not here", which invalidates the
// client's localized keys along with its cached state.
const usmStatsUnknownEngineIDs = "1.3.6.1.6.3.15.1.1.4.0"

// reportCounters holds the per-engine counters the two reports carry. They are
// counters of an engine's lifetime, so they live with the serving loop rather
// than being recomputed per request.
type reportCounters struct {
	notInTimeWindows uint32
	unknownEngineIDs uint32
}

// timeWindowSeconds is the ±150 seconds of RFC 3414 §2.2.3.
const timeWindowSeconds = 150

// engineBootsMax is the boots value at which RFC 3414 §2.2.2 says an engine may
// never be trusted as authoritative again, so every authenticated request is
// out of window from then on.
const engineBootsMax = 2147483647

// engineReport implements the two checks GoSNMPServer v0.5.2 leaves out
// entirely. It returns a Report PDU when a v3 request claims engine state this
// engine cannot serve — an engine ID that is not ours (RFC 3414 §3.2 (3)) or,
// on an authenticated message, one outside our time window (§3.2 (7b)) — along
// with the name of the counter reported, for the log. It returns nil when the
// request is ordinary, or is not the kind of message the checks apply to.
//
// The two checks sit in RFC order, and the order is the point: §3.2 (3) runs
// before the message is authenticated at step (6), while the timeliness check
// at (7) runs after. A request naming an engine that is not here is answered
// whatever its security level, because a noAuthNoPriv client caches an engine
// ID as surely as an authenticated one does.
//
// The rest of the request is not our business: a request answered with a report
// is discarded rather than answered, so the caller must send this instead of
// the response it would otherwise have built.
//
// The digest is not verified before reporting, which RFC 3414 §3.2 step 6 would
// have done first. That is not a gap these checks can close: neither gosnmp's
// SnmpDecodePacket nor GoSNMPServer verifies it either, so a forged request
// already gets a real answer out of this agent. Adding the check here alone
// would only make the reports stricter than the value they guard.
func engineReport(request []byte, master *server.MasterAgent, auth *AuthConfig, counts *reportCounters) ([]byte, string, error) {
	pkt, err := decodePacket(request, auth)
	if err != nil || pkt.Version != gosnmp.Version3 {
		// A message we cannot decode is one the library will refuse on its own
		// terms, and the checks apply to v3 alone.
		return nil, "", nil
	}
	// RFC 3412 §6.4: a report answers only a message that asked to be reported
	// on. Reporting on anything else invites two engines to report at each
	// other for ever.
	if pkt.MsgFlags&gosnmp.Reportable == 0 {
		return nil, "", nil
	}
	usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || usm == nil {
		return nil, "", nil
	}
	// The engine ID the agent is answering under right now, which the
	// engineIDChange fault moves: auth is the effective configuration, not
	// necessarily the one on disk.
	ourEngineID, err := auth.EngineIDBytes()
	if err != nil {
		return nil, "", nil
	}

	boots := master.SecurityConfig.AuthoritativeEngineBoots
	now := master.SecurityConfig.OnGetAuthoritativeEngineTime()

	// A message naming a different engine is not out of window, it is out of
	// scope, and the difference matters to the client: its cached engine state
	// is not merely stale, its localized keys are worthless too.
	//
	// An empty engine ID names no engine at all — that is discovery, the one
	// exchange the library does serve, and answering it here would take the
	// client's first message away from the code that knows how to reply to it.
	//
	// The counter counts the condition rather than the reports sent: RFC 3414
	// §3.2 increments it on detecting the message, before any report is built.
	if usm.AuthoritativeEngineID != "" && usm.AuthoritativeEngineID != ourEngineID {
		counts.unknownEngineIDs++
		msg, err := unknownEngineIDReport(pkt, ourEngineID, usm.UserName, boots, now, counts.unknownEngineIDs)
		return msg, "usmStatsUnknownEngineIDs", err
	}

	// RFC 3414 §3.2 (7): the timeliness check is on authenticated messages
	// only. An unauthenticated message claimed no engine state to be wrong
	// about.
	if pkt.MsgFlags&gosnmp.AuthNoPriv == 0 {
		return nil, "", nil
	}
	if inTimeWindow(usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime, boots, now) {
		return nil, "", nil
	}
	// ours is this user's credentials localized to our engine ID, which is what
	// the report has to be authenticated with.
	ours, err := auth.UsmUserWithEngine(usm.UserName)
	if err != nil {
		return nil, "", nil
	}
	counts.notInTimeWindows++
	msg, err := timelinessReport(pkt, ours, boots, now, counts.notInTimeWindows)
	return msg, "usmStatsNotInTimeWindows", err
}

// timelinessReport is the RFC 3414 §3.2 (7b) answer to an out-of-window
// request. It is sent at authNoPriv, authenticated with the requesting user's
// key, and carries this agent's real boots and time. A report the client cannot
// authenticate, or one that omits the current engine state, tells it nothing it
// can act on.
//
// reportUsm is the requesting user's credentials, localized to our engine ID,
// and is reshaped here into the report's own security parameters — so it must
// be a copy nobody else holds, which UsmUserWithEngine returns fresh per call.
func timelinessReport(pkt *gosnmp.SnmpPacket, reportUsm *gosnmp.UsmSecurityParameters, boots, now, count uint32) ([]byte, error) {
	reportUsm.AuthoritativeEngineBoots = boots
	reportUsm.AuthoritativeEngineTime = now
	// A report is authenticated but never encrypted, so drop the privacy
	// protocol before the keys are derived.
	reportUsm.PrivacyProtocol = gosnmp.NoPriv
	reportUsm.PrivacyPassphrase = ""
	if err := reportUsm.InitSecurityKeys(); err != nil {
		return nil, fmt.Errorf("initialising report keys for %q: %w", reportUsm.UserName, err)
	}
	return reportPDU(pkt, reportUsm, gosnmp.AuthNoPriv, usmStatsNotInTimeWindows, count)
}

// unknownEngineIDReport is the RFC 3414 §3.2 (3) answer to a request naming an
// engine ID that is not ours, and it is deliberately a different PDU from the
// timeliness report above: unauthenticated, because the client's keys are
// localized to the engine ID it named and it could not verify — nor could we
// produce — a digest either of us would agree on.
//
// What makes it useful is the engine ID it carries: the client's way back in is
// to re-discover this engine and re-localize its keys to the new value, and the
// report is where it learns that value.
func unknownEngineIDReport(pkt *gosnmp.SnmpPacket, engineID, username string, boots, now, count uint32) ([]byte, error) {
	usm := &gosnmp.UsmSecurityParameters{
		// The name is echoed back rather than dropped, so a client matching the
		// report against its outstanding request can see whose it was.
		UserName:                 username,
		AuthoritativeEngineID:    engineID,
		AuthoritativeEngineBoots: boots,
		AuthoritativeEngineTime:  now,
		AuthenticationProtocol:   gosnmp.NoAuth,
		PrivacyProtocol:          gosnmp.NoPriv,
	}
	return reportPDU(pkt, usm, gosnmp.NoAuthNoPriv, usmStatsUnknownEngineIDs, count)
}

// reportPDU assembles a Report answering pkt, carrying one counter varbind.
func reportPDU(pkt *gosnmp.SnmpPacket, usm *gosnmp.UsmSecurityParameters, flags gosnmp.SnmpV3MsgFlags, oid string, count uint32) ([]byte, error) {
	report := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           flags,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: usm,
		ContextEngineID:    usm.AuthoritativeEngineID,
		PDUType:            gosnmp.Report,
		// Both identifiers are echoed: the client matches the reply to its
		// outstanding request on the message ID, and RFC 3412 §7.1 has the
		// report carry the request ID that triggered it.
		MsgID:     pkt.MsgID,
		RequestID: pkt.RequestID,
		Variables: []gosnmp.SnmpPDU{{
			Name:  oid,
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
