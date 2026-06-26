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
	Auth     *AuthConfig
	Endpoint string
	Entries  []Entry
}

// newWebHandler wires up the HTTP routes for the UI.
func newWebHandler(auth *AuthConfig, store *Store, snmpEndpoint string) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.FileServer(http.FS(assets)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data := pageData{Auth: auth, Endpoint: snmpEndpoint, Entries: store.Entries()}
		render(w, "index.html", data)
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
