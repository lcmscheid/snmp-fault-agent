package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// TestLoadAuthFlatFileIsOneUser pins the backwards-compatible form: the original
// single-user file had the user's fields at the top level, and files written
// against that shape must keep working.
func TestLoadAuthFlatFileIsOneUser(t *testing.T) {
	path := writeTemp(t, "auth.json", `{
		"username": "testuser",
		"authProtocol": "SHA",
		"authPassphrase": "authpassword1",
		"privProtocol": "AES",
		"privPassphrase": "privpassword1",
		"engineID": "printer-lab-3"
	}`)

	cfg, err := LoadAuth(path)
	if err != nil {
		t.Fatalf("loading flat auth file: %v", err)
	}
	if len(cfg.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(cfg.Users))
	}
	u := cfg.Users[0]
	if u.Username != "testuser" {
		t.Errorf("username = %q, want testuser", u.Username)
	}
	if u.SecurityLevel() != "authPriv" {
		t.Errorf("security level = %q, want authPriv", u.SecurityLevel())
	}
	if cfg.EngineIDLabel() != "printer-lab-3" {
		t.Errorf("engine label = %q, want printer-lab-3", cfg.EngineIDLabel())
	}
}

// TestLoadAuthUsersArray covers the multi-user form, which is what makes an
// auth x priv matrix testable in a single process rather than one agent per
// combination.
func TestLoadAuthUsersArray(t *testing.T) {
	path := writeTemp(t, "auth.json", `{
		"engineID": "matrix",
		"community": "secret",
		"users": [
			{"username": "noauth"},
			{"username": "md5only", "authProtocol": "MD5", "authPassphrase": "authpassword1"},
			{"username": "sha256aes", "authProtocol": "SHA256", "authPassphrase": "authpassword1",
			 "privProtocol": "AES", "privPassphrase": "privpassword1"}
		]
	}`)

	cfg, err := LoadAuth(path)
	if err != nil {
		t.Fatalf("loading multi-user auth file: %v", err)
	}
	if len(cfg.Users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(cfg.Users))
	}
	if cfg.Community != "secret" {
		t.Errorf("community = %q, want secret", cfg.Community)
	}

	want := []string{"noAuthNoPriv", "authNoPriv", "authPriv"}
	for i, level := range want {
		if got := cfg.Users[i].SecurityLevel(); got != level {
			t.Errorf("user %d security level = %q, want %q", i, got, level)
		}
	}
}

// TestLoadAuthDefaultsCommunity keeps v2c reachable without configuration: the
// client library needs a v2c target from its very first stage, long before it
// can speak v3.
func TestLoadAuthDefaultsCommunity(t *testing.T) {
	path := writeTemp(t, "auth.json", `{"username": "testuser"}`)
	cfg, err := LoadAuth(path)
	if err != nil {
		t.Fatalf("loading auth: %v", err)
	}
	if cfg.Community != defaultCommunity {
		t.Errorf("community = %q, want the default %q", cfg.Community, defaultCommunity)
	}
	if !cfg.V2CEnabled() {
		t.Error("v2c should be enabled by default")
	}
}

// TestLoadAuthEmptyCommunityDisablesV2C is the escape hatch: an explicitly empty
// community means v3 only. It cannot be registered as a route because the empty
// string is already the v3 context name.
func TestLoadAuthEmptyCommunityDisablesV2C(t *testing.T) {
	path := writeTemp(t, "auth.json", `{"username": "testuser", "community": ""}`)
	cfg, err := LoadAuth(path)
	if err != nil {
		t.Fatalf("loading auth: %v", err)
	}
	if cfg.V2CEnabled() {
		t.Error("an explicitly empty community must disable v2c")
	}
}

// TestLoadAuthRejectsDuplicateUsernames catches a config that would otherwise
// fail confusingly at request time, since users are looked up by name.
func TestLoadAuthRejectsDuplicateUsernames(t *testing.T) {
	path := writeTemp(t, "auth.json", `{
		"users": [{"username": "same"}, {"username": "same"}]
	}`)
	if _, err := LoadAuth(path); err == nil {
		t.Fatal("expected duplicate usernames to be rejected")
	}
}

// TestLoadAuthRejectsNoUsers guards the case where the file parses but leaves
// the agent with nothing to authenticate.
func TestLoadAuthRejectsNoUsers(t *testing.T) {
	path := writeTemp(t, "auth.json", `{"engineID": "empty"}`)
	if _, err := LoadAuth(path); err == nil {
		t.Fatal("expected a file with no users to be rejected")
	}
}

// TestFindUser is what the fault path relies on to decode a request with the
// credentials of whichever user actually sent it.
func TestFindUser(t *testing.T) {
	cfg := &AuthConfig{Users: []UserConfig{
		{Username: "alice", AuthProtocol: "SHA", AuthPassphrase: "authpassword1"},
		{Username: "bob"},
	}}

	u, ok := cfg.FindUser("alice")
	if !ok {
		t.Fatal("alice should be found")
	}
	if u.authProto() != gosnmp.SHA {
		t.Errorf("alice auth protocol = %v, want SHA", u.authProto())
	}
	if _, ok := cfg.FindUser("carol"); ok {
		t.Error("carol should not be found")
	}
}

// TestUnknownProtocolIsRejected stops a typo in a protocol name from silently
// downgrading the agent to noAuthNoPriv, which would make a client's authPriv
// request fail for reasons nothing reports.
func TestUnknownProtocolIsRejected(t *testing.T) {
	path := writeTemp(t, "auth.json", `{"username": "u", "authProtocol": "SHA3"}`)
	if _, err := LoadAuth(path); err == nil {
		t.Fatal("expected an unknown auth protocol to be rejected")
	}

	path = writeTemp(t, "auth.json", `{"username": "u", "privProtocol": "TWOFISH"}`)
	if _, err := LoadAuth(path); err == nil {
		t.Fatal("expected an unknown privacy protocol to be rejected")
	}
}

// TestOverrideEngineID covers the -engineid flag: it beats the file, it is
// validated exactly as the file's value is, and a rejected override leaves the
// configured engine ID intact rather than half-applied — every user's keys are
// localized against it, so a partial override would be a silent key change.
func TestOverrideEngineID(t *testing.T) {
	cfg := &AuthConfig{EngineID: "printer-lab-3", Users: []UserConfig{{Username: "u"}}}

	if err := cfg.OverrideEngineID("switch-7"); err != nil {
		t.Fatalf("overriding with a label: %v", err)
	}
	if got := cfg.EngineIDLabel(); got != "switch-7" {
		t.Errorf("engine label = %q, want switch-7", got)
	}

	for _, bad := range []struct{ name, value string }{
		{"empty", ""},
		{"blank", "   "},
		{"invalid hex", "0xnothex"},
		{"too long", strings.Repeat("x", 28)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if err := cfg.OverrideEngineID(bad.value); err == nil {
				t.Fatalf("expected %q to be rejected", bad.value)
			}
			if got := cfg.EngineIDLabel(); got != "switch-7" {
				t.Errorf("a rejected override changed the engine ID to %q", got)
			}
		})
	}
}
