package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// UserConfig is one SNMPv3 USM user. The agent serves several at once so a
// client's protocol matrix — every auth protocol against every privacy protocol
// — can be exercised against a single running instance instead of one agent per
// combination.
type UserConfig struct {
	Username       string `json:"username"`
	AuthProtocol   string `json:"authProtocol"`   // none, MD5, SHA, SHA224, SHA256, SHA384, SHA512
	AuthPassphrase string `json:"authPassphrase"` // shared authentication secret
	PrivProtocol   string `json:"privProtocol"`   // none, DES, AES, AES192, AES256, AES192C, AES256C
	PrivPassphrase string `json:"privPassphrase"` // shared privacy secret
}

// AuthConfig is the agent's identity and credentials, loaded from the auth JSON
// file.
type AuthConfig struct {
	EngineID  string       `json:"engineID"`  // optional hex string or free-form label
	Community string       `json:"community"` // v2c community; empty disables v2c
	Users     []UserConfig `json:"users"`
}

// defaultCommunity is used when the auth file names none. v2c is on by default
// because a client under development reaches v2c long before it can speak v3,
// and an agent that has to be configured before it answers at all is friction
// in exactly the wrong place.
const defaultCommunity = "public"

// V2CEnabled reports whether the agent answers SNMPv1/v2c requests.
//
// An empty community is the off switch rather than a wildcard, because the
// empty string is already taken: the underlying library routes v3 by context
// name and v1/v2c by community through the same table, and the standard empty
// v3 context is registered under "".
func (a AuthConfig) V2CEnabled() bool { return a.Community != "" }

// SecurityLevel returns the SNMPv3 security level this user's protocols imply.
//
// Note that the agent *infers* the level here while an SNMP client should
// *require* it explicitly: a client that silently downgrades authPriv to
// authNoPriv has a security hole, whereas a test agent that accepts whatever
// arrives is merely convenient.
func (u UserConfig) SecurityLevel() string {
	auth := u.authProto() > gosnmp.NoAuth
	priv := u.privProto() > gosnmp.NoPriv
	switch {
	case auth && priv:
		return "authPriv"
	case auth:
		return "authNoPriv"
	default:
		return "noAuthNoPriv"
	}
}

// authProtocols maps the names accepted in the config file to gosnmp's
// constants. Lookup is on the upper-cased, trimmed name.
var authProtocols = map[string]gosnmp.SnmpV3AuthProtocol{
	"":       gosnmp.NoAuth,
	"NONE":   gosnmp.NoAuth,
	"NOAUTH": gosnmp.NoAuth,
	"MD5":    gosnmp.MD5,
	"SHA":    gosnmp.SHA,
	"SHA224": gosnmp.SHA224,
	"SHA256": gosnmp.SHA256,
	"SHA384": gosnmp.SHA384,
	"SHA512": gosnmp.SHA512,
}

// privProtocols maps config names to gosnmp's privacy constants. The C suffix
// on AES192C/AES256C marks the Reeder key-extension variant, which is
// incompatible with the plain Blumenthal form of the same cipher; both are
// offered so a client can be tested against either.
var privProtocols = map[string]gosnmp.SnmpV3PrivProtocol{
	"":        gosnmp.NoPriv,
	"NONE":    gosnmp.NoPriv,
	"NOPRIV":  gosnmp.NoPriv,
	"DES":     gosnmp.DES,
	"AES":     gosnmp.AES,
	"AES192":  gosnmp.AES192,
	"AES256":  gosnmp.AES256,
	"AES192C": gosnmp.AES192C,
	"AES256C": gosnmp.AES256C,
}

func protoKey(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

func (u UserConfig) authProto() gosnmp.SnmpV3AuthProtocol {
	return authProtocols[protoKey(u.AuthProtocol)]
}

func (u UserConfig) privProto() gosnmp.SnmpV3PrivProtocol {
	return privProtocols[protoKey(u.PrivProtocol)]
}

// validate rejects a user the agent could not serve as written. Unknown
// protocol names are an error rather than a fallback to "none": a typo that
// silently downgrades the user to noAuthNoPriv makes every authPriv request
// fail with nothing explaining why.
func (u UserConfig) validate() error {
	if strings.TrimSpace(u.Username) == "" {
		return errors.New("username is required")
	}
	if _, ok := authProtocols[protoKey(u.AuthProtocol)]; !ok {
		return fmt.Errorf("user %q: unknown authProtocol %q", u.Username, u.AuthProtocol)
	}
	if _, ok := privProtocols[protoKey(u.PrivProtocol)]; !ok {
		return fmt.Errorf("user %q: unknown privProtocol %q", u.Username, u.PrivProtocol)
	}
	if u.authProto() > gosnmp.NoAuth && u.AuthPassphrase == "" {
		return fmt.Errorf("user %q: authProtocol %s needs an authPassphrase", u.Username, u.AuthProtocol)
	}
	if u.privProto() > gosnmp.NoPriv && u.PrivPassphrase == "" {
		return fmt.Errorf("user %q: privProtocol %s needs a privPassphrase", u.Username, u.PrivProtocol)
	}
	// RFC 3414 §2.2: privacy without authentication is not a valid combination,
	// since the privacy key is derived from the authentication key.
	if u.privProto() > gosnmp.NoPriv && u.authProto() == gosnmp.NoAuth {
		return fmt.Errorf("user %q: privacy requires authentication (RFC 3414 §2.2)", u.Username)
	}
	return nil
}

// UsmUser converts the user into the gosnmp USM parameters the agent serves.
func (u UserConfig) UsmUser() gosnmp.UsmSecurityParameters {
	return gosnmp.UsmSecurityParameters{
		UserName:                 u.Username,
		AuthenticationProtocol:   u.authProto(),
		AuthenticationPassphrase: u.AuthPassphrase,
		PrivacyProtocol:          u.privProto(),
		PrivacyPassphrase:        u.PrivPassphrase,
	}
}

// UsmUsers returns every configured user, for the agent's security config.
func (a AuthConfig) UsmUsers() []gosnmp.UsmSecurityParameters {
	out := make([]gosnmp.UsmSecurityParameters, 0, len(a.Users))
	for _, u := range a.Users {
		out = append(out, u.UsmUser())
	}
	return out
}

// FindUser looks a user up by the name carried in a request.
func (a AuthConfig) FindUser(username string) (UserConfig, bool) {
	for _, u := range a.Users {
		if u.Username == username {
			return u, true
		}
	}
	return UserConfig{}, false
}

// UsmUserWithEngine returns the named user's USM parameters with this agent's
// authoritative engine ID attached, which is what lets us decode our own v3
// traffic: the privacy and authentication keys are localized to the engine ID
// (RFC 3414 §2.6), and without it key derivation produces a zero-length key.
//
// It returns a pointer because UsmSecurityParameters embeds a mutex, which must
// not be copied.
func (a AuthConfig) UsmUserWithEngine(username string) (*gosnmp.UsmSecurityParameters, error) {
	u, ok := a.FindUser(username)
	if !ok {
		return nil, fmt.Errorf("no configured user named %q", username)
	}
	data, err := a.EngineIDData()
	if err != nil {
		return nil, err
	}
	usm := u.UsmUser()
	usm.AuthoritativeEngineID = string(append(append([]byte{}, enginePrefix...), []byte(data)...))
	return &usm, nil
}

// defaultEngineLabel is the stable identity used when none is configured, so
// the engine ID never depends on the host the simulator runs on.
const defaultEngineLabel = "snmpfault"

// enginePrefix is the fixed 5-byte prefix GoSNMPServer always prepends to the
// engine ID data: pysnmp enterprise number (20408) + "octets" format byte.
var enginePrefix = []byte{0x80, 0x00, 0x4f, 0xb8, 0x05}

// EngineIDLabel returns the human-readable identity to display for this agent.
func (a AuthConfig) EngineIDLabel() string {
	if v := strings.TrimSpace(a.EngineID); v != "" {
		return v
	}
	return defaultEngineLabel
}

// EngineIDData returns the engine ID data portion (the octets that follow the
// fixed prefix). The configured value is treated as a free-form text label so
// it can read like a device identity (e.g. "printer-lab-3"); prefix it with
// "0x" to supply raw hex instead.
func (a AuthConfig) EngineIDData() (string, error) {
	v := a.EngineIDLabel()
	var data []byte
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		raw, err := hex.DecodeString(v[2:])
		if err != nil {
			return "", fmt.Errorf("engineID hex value is invalid: %w", err)
		}
		data = raw
	} else {
		data = []byte(v)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("engineID resolves to an empty value")
	}
	if len(data) > 27 {
		return "", fmt.Errorf("engineID is too long: %d bytes (max 27 after the 5-byte prefix)", len(data))
	}
	return string(data), nil
}

// WireEngineID returns the full hex engine ID as it appears on the wire, i.e.
// the fixed prefix followed by the data portion. This is the value an SNMP
// client must trust. Returns "" if the configured engineID is invalid.
func (a AuthConfig) WireEngineID() string {
	data, err := a.EngineIDData()
	if err != nil {
		return ""
	}
	return hex.EncodeToString(append(append([]byte{}, enginePrefix...), []byte(data)...))
}

// authFile is the on-disk shape of the auth JSON. It carries the multi-user
// form and, inline, the fields of the original single-user form, so files
// written against the earlier schema keep loading.
type authFile struct {
	EngineID  string       `json:"engineID"`
	Community *string      `json:"community"` // pointer so "unset" is distinguishable from ""
	Users     []UserConfig `json:"users"`

	// The flat single-user form.
	UserConfig
}

// LoadAuth reads and validates the auth JSON file.
func LoadAuth(path string) (*AuthConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f authFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	cfg := &AuthConfig{EngineID: f.EngineID, Users: f.Users}

	// An unset community means the default; an explicit "" means v2c off.
	if f.Community == nil {
		cfg.Community = defaultCommunity
	} else {
		cfg.Community = *f.Community
	}

	// The flat form: the user's fields sit at the top level. Accept it only when
	// there is no users array, so a file cannot half-use both shapes and leave
	// the reader guessing which one won.
	if len(cfg.Users) == 0 && strings.TrimSpace(f.Username) != "" {
		cfg.Users = []UserConfig{f.UserConfig}
	} else if len(cfg.Users) > 0 && strings.TrimSpace(f.Username) != "" {
		return nil, fmt.Errorf("%s: use either a top-level user or a \"users\" array, not both", path)
	}

	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("%s: no users defined", path)
	}

	seen := make(map[string]bool, len(cfg.Users))
	for i, u := range cfg.Users {
		if err := u.validate(); err != nil {
			return nil, fmt.Errorf("%s: user #%d: %w", path, i+1, err)
		}
		if seen[u.Username] {
			return nil, fmt.Errorf("%s: duplicate username %q", path, u.Username)
		}
		seen[u.Username] = true
	}

	if _, err := cfg.EngineIDData(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ValueFile is the on-disk representation of the values JSON file.
type ValueFile struct {
	Values []ValueDef `json:"values"`
}

// ValueDef describes a single OID and the set of values it may return.
type ValueDef struct {
	Name    string   `json:"name"`
	OID     string   `json:"oid"`
	Type    string   `json:"type"` // string, integer, gauge, counter, timeticks, oid
	Options []string `json:"values"`
	// ReadOnly refuses SET on this OID, so the agent answers with the readOnly
	// error. A client's SET error handling is otherwise unreachable without a
	// real device that happens to expose a non-writable object.
	ReadOnly bool `json:"readOnly"`
}

// LoadValues reads and validates the values JSON file.
func LoadValues(path string) ([]ValueDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vf ValueFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(vf.Values) == 0 {
		return nil, fmt.Errorf("%s: no values defined", path)
	}
	for i, v := range vf.Values {
		if strings.TrimSpace(v.OID) == "" {
			return nil, fmt.Errorf("%s: value #%d is missing an oid", path, i+1)
		}
		if len(v.Options) == 0 {
			return nil, fmt.Errorf("%s: %q has no values to choose from", path, v.OID)
		}
	}
	return vf.Values, nil
}
