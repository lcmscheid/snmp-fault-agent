package main

import (
	"bytes"
	"crypto/hmac"
	"fmt"

	"github.com/gosnmp/gosnmp"
	server "github.com/slayercat/GoSNMPServer"
)

// The counters an authoritative engine reports, in the order RFC 3414 §3.2
// checks them. Each names a different thing the client got wrong, and a client
// that cannot tell them apart cannot tell a wrong password from a dead network.
const (
	// usmStatsNotInTimeWindows answers a request whose claimed engine state is
	// outside this engine's window (§3.2 (7a)). It is the one report a client
	// can recover from by resynchronising, which is what makes the two engine
	// faults visible rather than merely reported.
	usmStatsNotInTimeWindows = "1.3.6.1.6.3.15.1.1.2.0"

	// usmStatsUnknownUserNames answers a request naming a user this engine does
	// not serve (§3.2 (4)).
	usmStatsUnknownUserNames = "1.3.6.1.6.3.15.1.1.3.0"

	// usmStatsUnknownEngineIDs answers a request naming an engine ID that is not
	// this engine's own (§3.2 (3)). It is a different answer to a different
	// question: not "your engine state is stale" but "the engine you are talking
	// to is not here", which invalidates the client's localized keys along with
	// its cached state.
	usmStatsUnknownEngineIDs = "1.3.6.1.6.3.15.1.1.4.0"

	// usmStatsWrongDigests answers a request whose digest does not verify under
	// the named user's key (§3.2 (6)) — a wrong authentication passphrase, or a
	// forgery.
	usmStatsWrongDigests = "1.3.6.1.6.3.15.1.1.5.0"

	// usmStatsDecryptionErrors answers an authentic request whose payload will
	// not decrypt (§3.2 (8)) — a wrong privacy passphrase. It is reachable only
	// after the digest verified, so it says the authentication passphrase was
	// right and the privacy one was not.
	usmStatsDecryptionErrors = "1.3.6.1.6.3.15.1.1.6.0"
)

// reportCounters holds the per-engine counters the reports carry. They are
// counters of an engine's lifetime, so they live with the serving loop rather
// than being recomputed per request.
type reportCounters struct {
	notInTimeWindows uint32
	unknownUserNames uint32
	unknownEngineIDs uint32
	wrongDigests     uint32
	decryptionErrors uint32
}

// timeWindowSeconds is the ±150 seconds of RFC 3414 §2.2.3.
const timeWindowSeconds = 150

// engineBootsMax is the boots value at which RFC 3414 §2.2.2 says an engine may
// never be trusted as authoritative again, so every authenticated request is
// out of window from then on.
const engineBootsMax = 2147483647

// engineReport implements the RFC 3414 §3.2 checks GoSNMPServer v0.5.2 leaves
// out entirely. A v3 request that claims engine state or credentials this
// engine cannot serve comes back with the name of the counter it incremented,
// and with the Report PDU answering it — or with no PDU, when the request did
// not ask to be reported on. The counter is the caller's signal either way: it
// means the request must not be answered. Both are empty when the request is
// ordinary, or is not the kind of message the checks apply to.
//
// The checks sit in RFC order, and the order is the point — each one may only
// assume what the ones before it established:
//
//	(3) the engine ID is ours, before anything is authenticated
//	(4) the user is one we serve, so there is a key to check against
//	(6) the digest verifies, so the message is authentic and the reply can be
//	(7) the engine state is inside our window
//	(8) the payload decrypts, which only an authentic message can be asked to do
//
// The security level of each report follows from where it sits in that list. A
// report answering (3), (4) or (6) is sent unauthenticated: this engine holds
// the correct key, and a client that named the wrong engine, no known user, or
// the wrong passphrase cannot verify a digest made with it. From (7) onwards
// the digest has verified, so the client shares our key and the report is
// authenticated with it.
//
// The rest of the request is not our business: a request that failed a check is
// discarded rather than answered, so the caller must send this — or nothing at
// all — instead of the response it would otherwise have built.
func engineReport(request []byte, master *server.MasterAgent, auth *AuthConfig, counts *reportCounters) ([]byte, string, error) {
	// The keyless pass reads the v3 header and stops there. That is all the
	// checks below need, and all a message we cannot decrypt will ever give us.
	head, _ := decodeHeader(request)
	if head == nil || head.Version != gosnmp.Version3 {
		// A message we cannot even read a header from is one the library will
		// refuse on its own terms, and the checks apply to v3 alone.
		return nil, "", nil
	}
	usm, ok := head.SecurityParameters.(*gosnmp.UsmSecurityParameters)
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
	reportable := head.MsgFlags&gosnmp.Reportable != 0

	// pkt is the request read as far as our keys allow: the whole message when
	// it yields to them, the header alone when it does not. A report echoes two
	// identifiers from it, and the failure to decrypt is itself step (8)'s
	// verdict, so the one decode serves both.
	pkt, decodeErr := decodePacket(request, auth)
	if decodeErr != nil || pkt == nil {
		pkt = head
	}

	// (3) A message naming a different engine is not out of window, it is out
	// of scope, and the difference matters to the client: its cached engine
	// state is not merely stale, its localized keys are worthless too.
	//
	// The counter counts the condition rather than the reports sent: RFC 3414
	// §3.2 increments it on detecting the message, before any report is built.
	if usm.AuthoritativeEngineID != "" && usm.AuthoritativeEngineID != ourEngineID {
		counts.unknownEngineIDs++
		return reported(reportable, "usmStatsUnknownEngineIDs", func() ([]byte, error) {
			return unauthenticatedReport(pkt, ourEngineID, usm.UserName, boots, now, usmStatsUnknownEngineIDs, counts.unknownEngineIDs)
		})
	}
	// An empty engine ID names no engine at all — that is discovery, the one
	// exchange the library does serve, and answering it here would take the
	// client's first message away from the code that knows how to reply to it.
	// Every check below would fire on it: discovery carries no user name and no
	// digest, by design.
	if usm.AuthoritativeEngineID == "" {
		return nil, "", nil
	}

	// (4) A user we do not serve has no key to check a digest against, so this
	// is as far as the message can be read.
	ours, err := auth.UsmUserWithEngine(usm.UserName)
	if err != nil {
		counts.unknownUserNames++
		return reported(reportable, "usmStatsUnknownUserNames", func() ([]byte, error) {
			return unauthenticatedReport(pkt, ourEngineID, usm.UserName, boots, now, usmStatsUnknownUserNames, counts.unknownUserNames)
		})
	}

	// Everything below is about credentials the message did not claim to carry.
	// An unauthenticated message, or one from a user configured without
	// authentication, is the library's to accept or refuse — the mismatch
	// between a claimed level and a configured one is §3.2 (5), which the
	// library already answers with ErrNoPermission.
	if head.MsgFlags&gosnmp.AuthNoPriv == 0 || ours.AuthenticationProtocol <= gosnmp.NoAuth {
		return nil, "", nil
	}
	if err := ours.InitSecurityKeys(); err != nil {
		return nil, "", nil
	}

	// (6) Until this passes the request is a forgery as far as this engine can
	// tell, and answering a forgery is what a real engine never does.
	if !authentic(request, ours, usm.AuthenticationParameters) {
		counts.wrongDigests++
		return reported(reportable, "usmStatsWrongDigests", func() ([]byte, error) {
			return unauthenticatedReport(pkt, ourEngineID, usm.UserName, boots, now, usmStatsWrongDigests, counts.wrongDigests)
		})
	}

	// (7) The timeliness check is on authenticated messages only, which is why
	// it sits below the gate above: an unauthenticated message claimed no
	// engine state to be wrong about.
	if !inTimeWindow(usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime, boots, now) {
		counts.notInTimeWindows++
		return reported(reportable, "usmStatsNotInTimeWindows", func() ([]byte, error) {
			return authenticatedReport(pkt, ours, boots, now, usmStatsNotInTimeWindows, counts.notInTimeWindows)
		})
	}

	// (8) The message is authentic and timely, so a payload that will not come
	// apart is a privacy key the client got wrong rather than anything about
	// the message itself. Only an encrypted message can fail this way; an
	// authNoPriv message that did not decode failed for some other reason, and
	// mislabelling that as a decryption error would send the client after the
	// wrong passphrase.
	if head.MsgFlags&gosnmp.AuthPriv == gosnmp.AuthPriv && ours.PrivacyProtocol > gosnmp.NoPriv && decodeErr != nil {
		counts.decryptionErrors++
		return reported(reportable, "usmStatsDecryptionErrors", func() ([]byte, error) {
			return authenticatedReport(pkt, ours, boots, now, usmStatsDecryptionErrors, counts.decryptionErrors)
		})
	}
	return nil, "", nil
}

// authentic reports whether a request's digest was made with this user's key
// (RFC 3414 §3.2 (6)). The digest covers the whole message with its own field
// zeroed, so the field is blanked here before the HMAC is recomputed — the same
// substitution gosnmp performs when it signs a message, run backwards, and
// located the same way: by searching for the bytes that belong there.
//
// Both RFC 3414 (MD5, SHA) and RFC 7860 (the SHA-2 family) authenticate with an
// HMAC over the localized key truncated to the field's width, so one comparison
// serves every protocol. The width is taken from the message rather than
// assumed, which is also what keeps a truncated or absent digest from matching.
func authentic(request []byte, usm *gosnmp.UsmSecurityParameters, received string) bool {
	if usm.AuthenticationProtocol <= gosnmp.NoAuth || received == "" {
		return false
	}
	blanked := scratchCopy(request)
	idx := bytes.Index(blanked, []byte(received))
	if idx < 0 {
		return false
	}
	for i := 0; i < len(received); i++ {
		blanked[idx+i] = 0
	}
	mac := hmac.New(usm.AuthenticationProtocol.HashType().New, usm.SecretKey)
	if _, err := mac.Write(blanked); err != nil {
		return false
	}
	sum := mac.Sum(nil)
	if len(received) > len(sum) {
		return false
	}
	return hmac.Equal([]byte(received), sum[:len(received)])
}

// reported packages a check's verdict. The counter comes back whatever the
// message's flags, because RFC 3414 §3.2 discards a message that failed a check
// either way and the caller must not answer it. The report itself is built only
// for a message that asked to be reported on (RFC 3412 §6.4): reporting on
// anything else invites two engines to report at each other for ever, and
// building an answer to a request that will not be sent one is work whose only
// outcome is a chance to send it by mistake.
func reported(reportable bool, counter string, build func() ([]byte, error)) ([]byte, string, error) {
	if !reportable {
		return nil, counter, nil
	}
	msg, err := build()
	return msg, counter, err
}

// authenticatedReport is the shape of a report a client can verify: sent at
// authNoPriv, authenticated with the requesting user's key, carrying this
// agent's own engine state. It answers §3.2 (7a), which requires that level,
// and §3.2 (8), which names none — but which is reached only once the digest
// has verified, so the client holds the key to check ours and a report it can
// check is what tells it which of the two passphrases to go and fix.
//
// reportUsm is the requesting user's credentials, localized to our engine ID,
// and is reshaped here into the report's own security parameters — so it must
// be a copy nobody else holds, which UsmUserWithEngine returns fresh per call.
func authenticatedReport(pkt *gosnmp.SnmpPacket, reportUsm *gosnmp.UsmSecurityParameters, boots, now uint32, oid string, count uint32) ([]byte, error) {
	reportUsm.AuthoritativeEngineBoots = boots
	reportUsm.AuthoritativeEngineTime = now
	// A report is authenticated but never encrypted, so drop the privacy
	// protocol before the keys are derived.
	reportUsm.PrivacyProtocol = gosnmp.NoPriv
	reportUsm.PrivacyPassphrase = ""
	if err := reportUsm.InitSecurityKeys(); err != nil {
		return nil, fmt.Errorf("initialising report keys for %q: %w", reportUsm.UserName, err)
	}
	return reportPDU(pkt, reportUsm, gosnmp.AuthNoPriv, oid, count)
}

// unauthenticatedReport is the shape of a report sent before this engine and
// the client are known to share a key — the answers to RFC 3414 §3.2 (3), (4)
// and (6). Signing one would not help: a client that named another engine, a
// user we do not have, or the wrong passphrase could not verify a digest of
// ours, and in the (4) case we have no key to make one with at all.
//
// What makes it useful is the engine ID it carries: a client whose way back in
// is to re-discover this engine and re-localize its keys learns the value here.
func unauthenticatedReport(pkt *gosnmp.SnmpPacket, engineID, username string, boots, now uint32, oid string, count uint32) ([]byte, error) {
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
	return reportPDU(pkt, usm, gosnmp.NoAuthNoPriv, oid, count)
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
		// report carry the request ID that triggered it. A request we could not
		// decrypt yields only the message ID, which is the one the client
		// matches on.
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
