package main

import (
	"bytes"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// The AES key-extension schemes are the reason this agent claims to settle a
// question that would otherwise need borrowed hardware, so the claim needs a
// test rather than a configuration that merely looks right.
//
// Blumenthal (AES192/AES256) and Reeder (AES192C/AES256C) both derive
//
//	localizedKey || extension
//
// and gosnmp then truncates that to the cipher's key length. The extension
// bytes are therefore only reached when the authentication hash is *shorter*
// than the key. Pair AES256C with SHA-256 and the 32-byte hash fills the key on
// its own: the extension is truncated away, and the two schemes — which are
// supposed to be mutually incompatible — produce byte-identical keys. A client
// that implemented neither would pass such a matrix.
//
// Hash output lengths, for reference: MD5 16, SHA 20, SHA224 28, SHA256 32,
// SHA384 48, SHA512 64. Key lengths: AES 16, AES192 24, AES256 32.

// derivePrivKey localizes a privacy key exactly as a client would, so the test
// compares what actually goes on the wire.
func derivePrivKey(t *testing.T, auth gosnmp.SnmpV3AuthProtocol, priv gosnmp.SnmpV3PrivProtocol, engineID string) []byte {
	t.Helper()
	usm := &gosnmp.UsmSecurityParameters{
		UserName:                 "u",
		AuthenticationProtocol:   auth,
		AuthenticationPassphrase: "authpassword1",
		PrivacyProtocol:          priv,
		PrivacyPassphrase:        "privpassword1",
		AuthoritativeEngineID:    engineID,
	}
	if err := usm.InitSecurityKeys(); err != nil {
		t.Fatalf("deriving key for %v/%v: %v", auth, priv, err)
	}
	return usm.PrivacyKey
}

// TestKeyExtensionSchemesDiffer is the assertion behind the claim that both
// schemes are verified on every commit: if a pairing makes them agree, that
// pairing tests nothing.
func TestKeyExtensionSchemesDiffer(t *testing.T) {
	const engineID = "\x80\x00\x4f\xb8\x05test-engine"

	cases := []struct {
		name       string
		auth       gosnmp.SnmpV3AuthProtocol
		blumenthal gosnmp.SnmpV3PrivProtocol
		reeder     gosnmp.SnmpV3PrivProtocol
	}{
		{"MD5/AES192", gosnmp.MD5, gosnmp.AES192, gosnmp.AES192C},
		{"MD5/AES256", gosnmp.MD5, gosnmp.AES256, gosnmp.AES256C},
		{"SHA/AES192", gosnmp.SHA, gosnmp.AES192, gosnmp.AES192C},
		{"SHA/AES256", gosnmp.SHA, gosnmp.AES256, gosnmp.AES256C},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := derivePrivKey(t, tc.auth, tc.blumenthal, engineID)
			r := derivePrivKey(t, tc.auth, tc.reeder, engineID)
			if bytes.Equal(b, r) {
				t.Fatalf("Blumenthal and Reeder derived the same %d-byte key, so this "+
					"pairing exercises neither scheme", len(b))
			}
		})
	}
}

// TestExampleConfigExercisesBothKeyExtensions is the guard that matters: it
// checks the *shipped* configuration, not a hand-picked pairing, so a future
// edit that quietly neuters the matrix fails here.
func TestExampleConfigExercisesBothKeyExtensions(t *testing.T) {
	auth, err := LoadAuth("examples/auth.json")
	if err != nil {
		t.Fatalf("loading auth: %v", err)
	}
	engineData, err := auth.EngineIDData()
	if err != nil {
		t.Fatalf("engine ID: %v", err)
	}
	engineID := string(append(append([]byte{}, enginePrefix...), []byte(engineData)...))

	// The counterpart cipher for each extended one, so a configured user can be
	// re-derived under the opposite scheme and the two compared.
	counterpart := map[gosnmp.SnmpV3PrivProtocol]gosnmp.SnmpV3PrivProtocol{
		gosnmp.AES192:  gosnmp.AES192C,
		gosnmp.AES256:  gosnmp.AES256C,
		gosnmp.AES192C: gosnmp.AES192,
		gosnmp.AES256C: gosnmp.AES256,
	}

	var blumenthal, reeder int
	for _, u := range auth.Users {
		other, extended := counterpart[u.privProto()]
		if !extended {
			continue
		}

		mine := derivePrivKey(t, u.authProto(), u.privProto(), engineID)
		theirs := derivePrivKey(t, u.authProto(), other, engineID)
		if bytes.Equal(mine, theirs) {
			// Not a failure on its own: pairing a long hash with an extended
			// cipher is a real combination deployed devices use, and worth
			// serving. It simply proves nothing about which scheme a client
			// implemented, so it does not count towards coverage.
			t.Logf("user %q (%s + %s) does not distinguish the schemes: the hash "+
				"already fills the key, so the extension is truncated away",
				u.Username, u.AuthProtocol, u.PrivProtocol)
			continue
		}

		switch u.privProto() {
		case gosnmp.AES192, gosnmp.AES256:
			blumenthal++
		case gosnmp.AES192C, gosnmp.AES256C:
			reeder++
		}
	}

	if blumenthal == 0 {
		t.Error("no configured user genuinely exercises the Blumenthal key extension: " +
			"pair AES192/AES256 with an auth hash shorter than the key (MD5 or SHA)")
	}
	if reeder == 0 {
		t.Error("no configured user genuinely exercises the Reeder key extension: " +
			"pair AES192C/AES256C with an auth hash shorter than the key (MD5 or SHA)")
	}
	t.Logf("%d users exercise Blumenthal, %d exercise Reeder", blumenthal, reeder)
}
