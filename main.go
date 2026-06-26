// Command snmpsim is a small SNMPv3 agent for testing SNMP applications.
//
// It serves a configurable set of OIDs over SNMPv3 and exposes a minimal
// htmx web UI to inspect the credentials and switch the value each OID
// returns. Each OID starts on a randomly chosen value from its list.
package main

import (
	"flag"
	"log"
	"math/rand"
	"net/http"
	"time"
)

func main() {
	endpoint := flag.String("endpoint", "0.0.0.0:1161", "UDP endpoint the SNMP agent listens on (host:port)")
	httpAddr := flag.String("http", ":8080", "address the web UI listens on (host:port)")
	authPath := flag.String("auth", "auth.json", "path to the SNMPv3 credentials JSON file")
	valuesPath := flag.String("values", "values.json", "path to the values JSON file")
	flag.Parse()

	auth, err := LoadAuth(*authPath)
	if err != nil {
		log.Fatalf("loading auth: %v", err)
	}
	defs, err := LoadValues(*valuesPath)
	if err != nil {
		log.Fatalf("loading values: %v", err)
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	store := NewStore(defs, rng)

	master, err := buildAgent(auth, store)
	if err != nil {
		log.Fatalf("building SNMP agent: %v", err)
	}

	// Run the SNMP agent in the background; the web UI runs on the main goroutine.
	go func() {
		if err := serveSNMP(*endpoint, master); err != nil {
			log.Fatalf("SNMP agent: %v", err)
		}
	}()

	handler := newWebHandler(auth, store, *endpoint)
	log.Printf("web UI on http://%s", *httpAddr)
	if err := http.ListenAndServe(*httpAddr, handler); err != nil {
		log.Fatalf("web UI: %v", err)
	}
}
