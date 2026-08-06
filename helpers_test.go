package main

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// testAuthJSON is the credential configuration every test runs against unless
// it declares its own. It is written out here, rather than loaded from
// examples/, so that editing the shipped example — a user-facing document — can
// never move the test suite. What examples/ has to guarantee is asserted on its
// own terms in examples_test.go.
//
// The full auth x privacy matrix is spelled out rather than generated: several
// tests loop over these users, and a reader should be able to see every
// combination being served without reconstructing it from a loop.
const testAuthJSON = `{
  "engineID": "printer-lab-3",
  "community": "public",
  "users": [
    {"username": "testuser",      "authProtocol": "SHA",    "authPassphrase": "authpassword1", "privProtocol": "AES",     "privPassphrase": "privpassword1"},
    {"username": "noauthuser"},
    {"username": "md5user",       "authProtocol": "MD5",    "authPassphrase": "authpassword1"},
    {"username": "md5des",        "authProtocol": "MD5",    "authPassphrase": "authpassword1", "privProtocol": "DES",     "privPassphrase": "privpassword1"},
    {"username": "sha224user",    "authProtocol": "SHA224", "authPassphrase": "authpassword1", "privProtocol": "AES",     "privPassphrase": "privpassword1"},
    {"username": "sha256user",    "authProtocol": "SHA256", "authPassphrase": "authpassword1", "privProtocol": "AES",     "privPassphrase": "privpassword1"},
    {"username": "sha384user",    "authProtocol": "SHA384", "authPassphrase": "authpassword1", "privProtocol": "AES",     "privPassphrase": "privpassword1"},
    {"username": "sha512user",    "authProtocol": "SHA512", "authPassphrase": "authpassword1", "privProtocol": "AES",     "privPassphrase": "privpassword1"},
    {"username": "blumenthal192", "authProtocol": "SHA",    "authPassphrase": "authpassword1", "privProtocol": "AES192",  "privPassphrase": "privpassword1"},
    {"username": "blumenthal256", "authProtocol": "SHA",    "authPassphrase": "authpassword1", "privProtocol": "AES256",  "privPassphrase": "privpassword1"},
    {"username": "reeder192",     "authProtocol": "SHA",    "authPassphrase": "authpassword1", "privProtocol": "AES192C", "privPassphrase": "privpassword1"},
    {"username": "reeder256",     "authProtocol": "SHA",    "authPassphrase": "authpassword1", "privProtocol": "AES256C", "privPassphrase": "privpassword1"},
    {"username": "md5reeder256",  "authProtocol": "MD5",    "authPassphrase": "authpassword1", "privProtocol": "AES256C", "privPassphrase": "privpassword1"},
    {"username": "sha384aes192",  "authProtocol": "SHA384", "authPassphrase": "authpassword1", "privProtocol": "AES192",  "privPassphrase": "privpassword1"},
    {"username": "sha512aes256",  "authProtocol": "SHA512", "authPassphrase": "authpassword1", "privProtocol": "AES256",  "privPassphrase": "privpassword1"}
  ]
}`

// testValuesJSON is the OID set behind startTestAgent. It covers every value
// type the agent serves, and both a read-only and a writable OID, because tests
// across four files depend on all of those being present.
const testValuesJSON = `{
  "values": [
    {"name": "System Description", "oid": "1.3.6.1.2.1.1.1.0",       "type": "string",    "readOnly": true, "values": ["Router model A", "Router model B", "Router model C"]},
    {"name": "System Uptime",      "oid": "1.3.6.1.2.1.1.3.0",       "type": "timeticks", "readOnly": true, "values": ["1000", "500000", "99999999"]},
    {"name": "System Contact",     "oid": "1.3.6.1.2.1.1.4.0",       "type": "string",                      "values": ["noc@example.com", "unset"]},
    {"name": "System Location",    "oid": "1.3.6.1.2.1.1.6.0",       "type": "string",                      "values": ["rack 4, row B", "unset"]},
    {"name": "ifOperStatus.1",     "oid": "1.3.6.1.2.1.2.2.1.8.1",   "type": "integer",                     "values": ["1", "2"]},
    {"name": "ifInOctets.1",       "oid": "1.3.6.1.2.1.2.2.1.10.1",  "type": "counter",   "readOnly": true, "values": ["0", "123456", "4000000000"]},
    {"name": "Temperature (C)",    "oid": "1.3.6.1.4.1.9999.1.1.0",  "type": "gauge",                       "values": ["20", "45", "85"]}
  ]
}`

// startTestAgent brings up the agent on a free UDP port using the default test
// configuration, and returns the endpoint plus the fault set controlling it.
func startTestAgent(t *testing.T) (string, *Faults) {
	t.Helper()
	return startAgentJSON(t, testAuthJSON, testValuesJSON)
}

// startAgentJSON brings up the agent from configuration written literally in
// the test, so a test that turns on a particular config carries that config
// where it can be read. Both documents go through the real loaders, so a test
// cannot accidentally construct a configuration the file format cannot express.
func startAgentJSON(t *testing.T, authJSON, valuesJSON string) (string, *Faults) {
	t.Helper()
	return startAgentWith(t,
		writeTemp(t, "auth.json", authJSON),
		writeTemp(t, "values.json", valuesJSON))
}

// testAuth parses testAuthJSON, for tests that loop over the users the agent
// was started with.
func testAuth(t *testing.T) *AuthConfig {
	t.Helper()
	auth, err := LoadAuth(writeTemp(t, "auth.json", testAuthJSON))
	if err != nil {
		t.Fatalf("loading the test auth config: %v", err)
	}
	return auth
}

// testValues parses testValuesJSON, for tests that need the definitions without
// an agent in front of them.
func testValues(t *testing.T) []ValueDef {
	t.Helper()
	defs, err := LoadValues(writeTemp(t, "values.json", testValuesJSON))
	if err != nil {
		t.Fatalf("loading the test values config: %v", err)
	}
	return defs
}

// startAgentWith brings up the agent from named config files, so a test can
// vary the credentials or the served OIDs.
func startAgentWith(t *testing.T, authPath, valuesPath string) (string, *Faults) {
	t.Helper()

	auth, err := LoadAuth(authPath)
	if err != nil {
		t.Fatalf("loading auth: %v", err)
	}
	defs, err := LoadValues(valuesPath)
	if err != nil {
		t.Fatalf("loading values: %v", err)
	}

	store := NewStore(defs, rand.New(rand.NewSource(1)))
	faults := &Faults{}

	master, err := buildAgent(auth, store, faults)
	if err != nil {
		t.Fatalf("building agent: %v", err)
	}

	// Bind first and serve on the socket we hold, rather than asking the kernel
	// for a port, releasing it and hoping to get it back. That removes both the
	// race and the sleep that used to paper over it, and it gives the test
	// something to close: without it every test would leak a goroutine and a
	// listener for the life of the process.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding agent socket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A closed socket ends the loop; that is the expected shutdown, so the
		// error it returns is not worth reporting.
		_ = serveConn(conn, master, faults, auth)
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})

	return conn.LocalAddr().String(), faults
}

// splitEndpoint breaks a host:port string into the pair gosnmp wants.
func splitEndpoint(t *testing.T, endpoint string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatalf("splitting endpoint: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parsing port: %v", err)
	}
	return host, port
}

// connect completes client setup and registers cleanup.
func connect(t *testing.T, client *gosnmp.GoSNMP) *gosnmp.GoSNMP {
	t.Helper()
	if err := client.Connect(); err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { client.Conn.Close() })
	return client
}

// newClient returns a v3 client for the default user in testAuthJSON.
func newClient(t *testing.T, endpoint string) *gosnmp.GoSNMP {
	t.Helper()
	return newUserClient(t, endpoint, UserConfig{
		Username:       "testuser",
		AuthProtocol:   "SHA",
		AuthPassphrase: "authpassword1",
		PrivProtocol:   "AES",
		PrivPassphrase: "privpassword1",
	})
}

// newUserClient returns a v3 client configured for one user, with the message
// flags matching that user's security level. The level is derived here rather
// than passed in so a test cannot accidentally request authPriv from a
// noAuthNoPriv user and blame the agent.
func newUserClient(t *testing.T, endpoint string, u UserConfig) *gosnmp.GoSNMP {
	t.Helper()
	host, port := splitEndpoint(t, endpoint)

	flags := gosnmp.NoAuthNoPriv
	switch u.SecurityLevel() {
	case "authNoPriv":
		flags = gosnmp.AuthNoPriv
	case "authPriv":
		flags = gosnmp.AuthPriv
	}

	return connect(t, &gosnmp.GoSNMP{
		Target:        host,
		Port:          port,
		Version:       gosnmp.Version3,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      flags,
		Timeout:       2 * time.Second,
		Retries:       0,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 u.Username,
			AuthenticationProtocol:   u.authProto(),
			AuthenticationPassphrase: u.AuthPassphrase,
			PrivacyProtocol:          u.privProto(),
			PrivacyPassphrase:        u.PrivPassphrase,
		},
	})
}

// newV2CClient returns a v2c client using the default community.
func newV2CClient(t *testing.T, endpoint string) *gosnmp.GoSNMP {
	t.Helper()
	host, port := splitEndpoint(t, endpoint)

	return connect(t, &gosnmp.GoSNMP{
		Target:    host,
		Port:      port,
		Version:   gosnmp.Version2c,
		Community: defaultCommunity,
		Timeout:   2 * time.Second,
		Retries:   0,
	})
}
