package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// AuthConfig holds the SNMPv3 USM credentials loaded from the auth JSON file.
type AuthConfig struct {
	Username       string `json:"username"`
	AuthProtocol   string `json:"authProtocol"`   // none, MD5, SHA, SHA224, SHA256, SHA384, SHA512
	AuthPassphrase string `json:"authPassphrase"` // shared authentication secret
	PrivProtocol   string `json:"privProtocol"`   // none, DES, AES, AES192, AES256, AES192C, AES256C
	PrivPassphrase string `json:"privPassphrase"` // shared privacy secret
	EngineID       string `json:"engineID"`       // optional hex string; default derived from host
}

// SecurityLevel returns a human readable SNMPv3 security level for display.
func (a AuthConfig) SecurityLevel() string {
	auth := a.authProto() > gosnmp.NoAuth
	priv := a.privProto() > gosnmp.NoPriv
	switch {
	case auth && priv:
		return "authPriv"
	case auth:
		return "authNoPriv"
	default:
		return "noAuthNoPriv"
	}
}

func (a AuthConfig) authProto() gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(strings.TrimSpace(a.AuthProtocol)) {
	case "", "NONE", "NOAUTH":
		return gosnmp.NoAuth
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func (a AuthConfig) privProto() gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(strings.TrimSpace(a.PrivProtocol)) {
	case "", "NONE", "NOPRIV":
		return gosnmp.NoPriv
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	case "AES192C":
		return gosnmp.AES192C
	case "AES256C":
		return gosnmp.AES256C
	default:
		return gosnmp.NoPriv
	}
}

// UsmUser converts the config into the gosnmp USM parameters used by the agent.
func (a AuthConfig) UsmUser() gosnmp.UsmSecurityParameters {
	return gosnmp.UsmSecurityParameters{
		UserName:                 a.Username,
		AuthenticationProtocol:   a.authProto(),
		AuthenticationPassphrase: a.AuthPassphrase,
		PrivacyProtocol:          a.privProto(),
		PrivacyPassphrase:        a.PrivPassphrase,
	}
}

// EngineIDData returns the decoded engine ID data portion (may be empty).
func (a AuthConfig) EngineIDData() (string, error) {
	if strings.TrimSpace(a.EngineID) == "" {
		return "", nil
	}
	raw, err := hex.DecodeString(strings.TrimSpace(a.EngineID))
	if err != nil {
		return "", fmt.Errorf("engineID must be a hex string: %w", err)
	}
	return string(raw), nil
}

// LoadAuth reads and validates the auth JSON file.
func LoadAuth(path string) (*AuthConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg AuthConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, fmt.Errorf("%s: username is required", path)
	}
	if _, err := cfg.EngineIDData(); err != nil {
		return nil, err
	}
	return &cfg, nil
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
