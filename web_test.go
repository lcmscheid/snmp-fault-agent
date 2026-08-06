package main

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestHandler builds the web UI over the default test configuration.
func newTestHandler(t *testing.T) (http.Handler, *AuthConfig) {
	t.Helper()

	auth := testAuth(t)
	store := NewStore(testValues(t), rand.New(rand.NewSource(1)))
	return newWebHandler(auth, store, &Faults{}, "127.0.0.1:1161"), auth
}

// TestIndexRenders is a compile check the compiler cannot do: a template
// referring to a field that no longer exists fails only when the page is
// served, which in a tool driven by curl from a test suite means the first
// person to notice is a user.
func TestIndexRenders(t *testing.T) {
	handler, auth := newTestHandler(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// Every configured user must be listed, not just the first.
	for _, u := range auth.Users {
		if !strings.Contains(body, u.Username) {
			t.Errorf("index page does not mention user %q", u.Username)
		}
	}
	if !strings.Contains(body, auth.Community) {
		t.Errorf("index page does not show the v2c community %q", auth.Community)
	}
	if !strings.Contains(body, auth.WireEngineID()) {
		t.Error("index page does not show the wire engine ID")
	}
	if !strings.Contains(body, "read-only") {
		t.Error("index page does not mark the read-only values")
	}
}

// TestFaultEndpointsStillDrive covers the HTTP control surface tests use to
// toggle faults, since that is how CI drives the agent.
func TestFaultEndpointsStillDrive(t *testing.T) {
	handler, _ := newTestHandler(t)

	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := post("/faults", "name=tooBig&value=on"); rec.Code != http.StatusOK {
		t.Fatalf("enabling a fault = %d, body: %s", rec.Code, rec.Body.String())
	}
	if rec := post("/faults", "name=nosuchfault&value=on"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown fault = %d, want 400", rec.Code)
	}
	if rec := post("/faults/clear", ""); rec.Code != http.StatusOK {
		t.Fatalf("clearing faults = %d", rec.Code)
	}
}
