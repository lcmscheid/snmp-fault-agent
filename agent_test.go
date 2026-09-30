package main

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

const (
	sysContact  = "1.3.6.1.2.1.1.4.0"
	ifOperState = "1.3.6.1.2.1.2.2.1.8.1"
	sysObjects  = "1.3.6.1.2.1.1"
)

// TestV2CGet is the reason v2c exists here at all: a client is built and tested
// at v2c long before it can speak v3, and it needs a fault-injecting target for
// that whole stage.
func TestV2CGet(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newV2CClient(t, endpoint)

	res, err := client.Get([]string{sysDescr})
	if err != nil {
		t.Fatalf("v2c GET failed: %v", err)
	}
	if res.Error != gosnmp.NoError {
		t.Fatalf("expected NoError, got %v", res.Error)
	}
	if len(res.Variables) != 1 {
		t.Fatalf("expected 1 varbind, got %d", len(res.Variables))
	}
}

// TestV2CWalk covers GETNEXT, which a walk is built from, over v2c.
func TestV2CWalk(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newV2CClient(t, endpoint)

	results, err := client.WalkAll(sysObjects)
	if err != nil {
		t.Fatalf("v2c walk failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected the walk to return varbinds")
	}
}

// TestV2CWrongCommunityIsRefused checks the community actually gates access
// rather than being decorative.
func TestV2CWrongCommunityIsRefused(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newV2CClient(t, endpoint)
	client.Community = "wrong"

	res, err := client.Get([]string{sysDescr})
	if err == nil && res != nil && res.Error == gosnmp.NoError {
		t.Fatal("expected a request with the wrong community to be refused")
	}
}

// TestV2CFaultsApply guards the fault path across versions: the semantic faults
// decode and re-marshal the response, and that path is version-aware since v2c
// carries no security parameters to re-derive.
func TestV2CFaultsApply(t *testing.T) {
	endpoint, faults := startTestAgent(t)
	if err := faults.Set("tooBig", "on"); err != nil {
		t.Fatalf("setting fault: %v", err)
	}
	t.Cleanup(faults.Clear)

	client := newV2CClient(t, endpoint)
	res, err := client.Get([]string{sysDescr})
	if err != nil {
		t.Fatalf("v2c GET with fault failed: %v", err)
	}
	if res.Error != gosnmp.TooBig {
		t.Fatalf("expected TooBig at v2c, got %v", res.Error)
	}
}

// TestSetRoundTrip is the core of SET support: what a client writes must be
// what a subsequent read returns, otherwise the operation is untestable.
func TestSetRoundTrip(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newClient(t, endpoint)

	const want = "someone-new@example.com"
	res, err := client.Set([]gosnmp.SnmpPDU{{
		Name:  sysContact,
		Type:  gosnmp.OctetString,
		Value: want,
	}})
	if err != nil {
		t.Fatalf("SET failed: %v", err)
	}
	if res.Error != gosnmp.NoError {
		t.Fatalf("expected NoError on SET, got %v", res.Error)
	}

	got, err := client.Get([]string{sysContact})
	if err != nil {
		t.Fatalf("GET after SET failed: %v", err)
	}
	if v := string(got.Variables[0].Value.([]byte)); v != want {
		t.Errorf("GET after SET returned %q, want %q", v, want)
	}
}

// TestSetIntegerRoundTrip covers a non-string type, where the value has to be
// converted back from the Go type gosnmp decodes it into.
func TestSetIntegerRoundTrip(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newClient(t, endpoint)

	res, err := client.Set([]gosnmp.SnmpPDU{{
		Name:  ifOperState,
		Type:  gosnmp.Integer,
		Value: 2,
	}})
	if err != nil {
		t.Fatalf("SET failed: %v", err)
	}
	if res.Error != gosnmp.NoError {
		t.Fatalf("expected NoError on SET, got %v", res.Error)
	}

	got, err := client.Get([]string{ifOperState})
	if err != nil {
		t.Fatalf("GET after SET failed: %v", err)
	}
	if v := got.Variables[0].Value.(int); v != 2 {
		t.Errorf("GET after SET returned %d, want 2", v)
	}
}

// TestSetReadOnlyIsRefused reaches a client path that otherwise needs a real
// device exposing a non-writable object. The refusal is notWritable: RFC 3416
// §4.2 keeps readOnly for SNMPv1 compatibility only and says an SNMPv2 entity
// never generates it (#10).
func TestSetReadOnlyIsRefused(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newClient(t, endpoint)

	res, err := client.Set([]gosnmp.SnmpPDU{{
		Name:  sysDescr,
		Type:  gosnmp.OctetString,
		Value: "should not stick",
	}})
	if err != nil {
		t.Fatalf("SET request failed outright: %v", err)
	}
	if res.Error != gosnmp.NotWritable {
		t.Fatalf("expected notWritable, got %v", res.Error)
	}
	// error-index names the refused varbind, counting from 1 (#12).
	if res.ErrorIndex != 1 {
		t.Fatalf("expected error-index 1, got %d", res.ErrorIndex)
	}

	// And the value must be unchanged.
	got, err := client.Get([]string{sysDescr})
	if err != nil {
		t.Fatalf("GET after refused SET failed: %v", err)
	}
	if v := string(got.Variables[0].Value.([]byte)); v == "should not stick" {
		t.Error("a refused SET must not change the value")
	}
}

// TestSetWrongTypeIsRefused checks that writing the wrong type fails rather
// than silently succeeding, which is what a permissive agent would do, and
// fails with the wrongType RFC 3416 §4.2.5 names for it rather than genErr.
func TestSetWrongTypeIsRefused(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newClient(t, endpoint)

	res, err := client.Set([]gosnmp.SnmpPDU{{
		Name:  ifOperState,
		Type:  gosnmp.OctetString,
		Value: "not an integer",
	}})
	if err != nil {
		t.Fatalf("SET request failed outright: %v", err)
	}
	if res.Error != gosnmp.WrongType {
		t.Fatalf("expected wrongType, got %v", res.Error)
	}
	if res.ErrorIndex != 1 {
		t.Fatalf("expected error-index 1, got %d", res.ErrorIndex)
	}
}

// TestSetOverV2C confirms SET is not accidentally v3-only.
func TestSetOverV2C(t *testing.T) {
	endpoint, _ := startTestAgent(t)
	client := newV2CClient(t, endpoint)

	const want = "rack 9, row Z"
	if _, err := client.Set([]gosnmp.SnmpPDU{{
		Name:  "1.3.6.1.2.1.1.6.0",
		Type:  gosnmp.OctetString,
		Value: want,
	}}); err != nil {
		t.Fatalf("v2c SET failed: %v", err)
	}

	got, err := client.Get([]string{"1.3.6.1.2.1.1.6.0"})
	if err != nil {
		t.Fatalf("v2c GET after SET failed: %v", err)
	}
	if v := string(got.Variables[0].Value.([]byte)); v != want {
		t.Errorf("v2c GET after SET returned %q, want %q", v, want)
	}
}

// TestUserMatrix is what multi-user support is for: every auth x priv
// combination a client must handle, served by one agent, so the client's
// protocol matrix is a loop over users rather than a fleet of agents.
func TestUserMatrix(t *testing.T) {
	endpoint, _ := startTestAgent(t)

	auth := testAuth(t)
	if len(auth.Users) < 5 {
		t.Fatalf("the example config should exercise a real matrix, got %d users", len(auth.Users))
	}

	for _, u := range auth.Users {
		t.Run(u.Username, func(t *testing.T) {
			client := newUserClient(t, endpoint, u)
			res, err := client.Get([]string{sysDescr})
			if err != nil {
				t.Fatalf("GET as %s (%s) failed: %v", u.Username, u.SecurityLevel(), err)
			}
			if res.Error != gosnmp.NoError {
				t.Fatalf("GET as %s returned %v", u.Username, res.Error)
			}
		})
	}
}

// TestFaultsUnderEachUser is the multi-user version of the test that matters
// most: the fault path decodes and re-authenticates the agent's own response,
// and it must pick the credentials of whoever actually sent the request. With
// one user a hardcoded lookup would pass; with several it has to be right.
func TestFaultsUnderEachUser(t *testing.T) {
	endpoint, faults := startTestAgent(t)

	auth := testAuth(t)

	if err := faults.Set("tooBig", "on"); err != nil {
		t.Fatalf("setting fault: %v", err)
	}
	t.Cleanup(faults.Clear)

	for _, u := range auth.Users {
		t.Run(u.Username, func(t *testing.T) {
			client := newUserClient(t, endpoint, u)
			res, err := client.Get([]string{sysDescr})
			if err != nil {
				t.Fatalf("faulted GET as %s failed — a digest or decryption error here "+
					"means the fault path used the wrong user's keys: %v", u.Username, err)
			}
			if res.Error != gosnmp.TooBig {
				t.Errorf("expected TooBig as %s, got %v", u.Username, res.Error)
			}
		})
	}
}

// TestUnknownUserIsRefused checks that serving several users did not turn into
// serving anyone.
func TestUnknownUserIsRefused(t *testing.T) {
	endpoint, _ := startTestAgent(t)

	client := newUserClient(t, endpoint, UserConfig{
		Username:       "nobody",
		AuthProtocol:   "SHA",
		AuthPassphrase: "authpassword1",
		PrivProtocol:   "AES",
		PrivPassphrase: "privpassword1",
	})
	if res, err := client.Get([]string{sysDescr}); err == nil && res.Error == gosnmp.NoError {
		t.Fatal("expected an unconfigured user to be refused")
	}
}

// TestV2CDisabledIsRefused covers a mode the example config cannot demonstrate,
// because an example that answers nothing at v2c would be a poor example: an
// empty community turns v2c off entirely. The configuration is written out here
// so the thing under test is visible next to the assertion.
func TestV2CDisabledIsRefused(t *testing.T) {
	const authJSON = `{
	  "engineID": "printer-lab-3",
	  "community": "",
	  "users": [
	    {"username": "testuser", "authProtocol": "SHA", "authPassphrase": "authpassword1",
	     "privProtocol": "AES", "privPassphrase": "privpassword1"}
	  ]
	}`
	const valuesJSON = `{
	  "values": [
	    {"name": "System Description", "oid": "1.3.6.1.2.1.1.1.0", "type": "string",
	     "readOnly": true, "values": ["Router model A"]}
	  ]
	}`

	endpoint, _ := startAgentJSON(t, authJSON, valuesJSON)

	v2c := newV2CClient(t, endpoint)
	if res, err := v2c.Get([]string{sysDescr}); err == nil && res.Error == gosnmp.NoError {
		t.Error("expected v2c to be refused when no community is configured")
	}

	// v3 must be unaffected: disabling v2c is a narrowing of the surface, not a
	// broken agent.
	res, err := newClient(t, endpoint).Get([]string{sysDescr})
	if err != nil {
		t.Fatalf("v3 GET failed with v2c disabled: %v", err)
	}
	if res.Error != gosnmp.NoError {
		t.Fatalf("expected NoError over v3, got %v", res.Error)
	}
}
