package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"strconv"
)

//go:embed templates/*.html static/*
var assets embed.FS

var tmpl = template.Must(template.ParseFS(assets, "templates/*.html"))

// pageData is the model passed to the index template.
type pageData struct {
	Auth *AuthConfig
	// Engine is Auth as the agent is currently answering: the engineIDChange
	// fault replaces the engine ID, and a page still showing the configured one
	// would be handing out the value that no longer works — the wire form on it
	// is what a client needs for net-snmp's -e.
	Engine   *AuthConfig
	Endpoint string
	Entries  []Entry
	Faults   FaultSet
}

// newWebHandler wires up the HTTP routes for the UI.
func newWebHandler(auth *AuthConfig, store *Store, faults *Faults, snmpEndpoint string) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.FileServer(http.FS(assets)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		active := faults.Snapshot()
		data := pageData{
			Auth:     auth,
			Engine:   active.EffectiveAuth(auth),
			Endpoint: snmpEndpoint,
			Entries:  store.Entries(),
			Faults:   active,
		}
		render(w, "index.html", data)
	})

	// /faults sets one named fault and returns the refreshed summary line.
	// An unchecked checkbox posts no value at all, so an empty value means off.
	mux.HandleFunc("/faults", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.FormValue("name")
		value := r.FormValue("value")
		if value == "" {
			value = "off"
		}
		if err := faults.Set(name, value); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		active := faults.Snapshot()
		log.Printf("UI faults -> %s", active.Describe())
		render(w, "faults.html", active.Describe())
	})

	// /faults/clear disables every fault at once, so a test can return the
	// agent to well-behaved without unticking each box.
	mux.HandleFunc("/faults/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		faults.Clear()
		log.Printf("UI faults cleared")
		render(w, "faults.html", faults.Snapshot().Describe())
	})

	// /set selects the active value for an OID and returns the refreshed row.
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		oid := r.FormValue("oid")
		index, err := strconv.Atoi(r.FormValue("index"))
		if err != nil {
			http.Error(w, "invalid index", http.StatusBadRequest)
			return
		}
		entry, err := store.Set(oid, index)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("UI set %s -> %q", entry.OID, entry.Current())
		render(w, "row.html", entry)
	})

	return mux
}

func render(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
