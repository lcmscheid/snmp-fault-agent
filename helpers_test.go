package main

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// startTestAgent brings up the agent on a free UDP port using the example
// configuration, and returns the endpoint plus the fault set controlling it.
func startTestAgent(t *testing.T) (string, *Faults) {
	t.Helper()
	return startAgentWith(t, "examples/auth.json", "examples/values.json")
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

// newClient returns a v3 client for the default user in examples/auth.json.
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
