package main

import (
	"log"

	"github.com/gosnmp/gosnmp"
	"github.com/sirupsen/logrus"
	server "github.com/slayercat/GoSNMPServer"
)

// agentLogger returns an Info-level logger so the agent reports activity
// without the firehose of the library's default Trace level.
func agentLogger() server.ILogger {
	l := logrus.New()
	l.SetLevel(logrus.InfoLevel)
	return server.WrapLogrus(l)
}

// buildAgent constructs an SNMPv3-only master agent that serves the current
// value of every OID in the store using the supplied credentials.
func buildAgent(auth *AuthConfig, store *Store) (*server.MasterAgent, error) {
	engineID, err := auth.EngineIDData()
	if err != nil {
		return nil, err
	}

	oids := make([]*server.PDUValueControlItem, 0, len(store.entries))
	for _, e := range store.entries {
		oid := e.OID
		oidType, _, encErr := encodeValue(e.Type, e.Current())
		if encErr != nil {
			return nil, encErr
		}
		oids = append(oids, &server.PDUValueControlItem{
			OID:      oid,
			Type:     oidType,
			Document: e.Name,
			OnGet: func() (interface{}, error) {
				_, val, getErr := store.snmpValue(oid)
				if getErr != nil {
					return nil, getErr
				}
				return val, nil
			},
		})
	}

	sec := server.SecurityConfig{
		SnmpV3Only: true,
		Users:      []gosnmp.UsmSecurityParameters{auth.UsmUser()},
	}
	if engineID != "" {
		sec.AuthoritativeEngineID = server.SNMPEngineID{EngineIDData: engineID}
	}

	master := &server.MasterAgent{
		Logger:         agentLogger(),
		SecurityConfig: sec,
		SubAgents: []*server.SubAgent{
			{
				// SNMPv3 routes by context name; standard clients send an empty
				// context, so register this sub-agent under the empty context.
				CommunityIDs: []string{""},
				OIDs:         oids,
			},
		},
	}
	return master, nil
}

// serveSNMP starts the SNMP agent on the given UDP endpoint and blocks.
func serveSNMP(endpoint string, master *server.MasterAgent) error {
	srv := server.NewSNMPServer(*master)
	if err := srv.ListenUDP("udp", endpoint); err != nil {
		return err
	}
	log.Printf("SNMP agent listening on udp %s", endpoint)
	return srv.ServeForever()
}
