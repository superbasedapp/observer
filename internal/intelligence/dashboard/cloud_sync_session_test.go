package dashboard

import (
	"net/http"
	"reflect"
	"testing"
)

func TestCloudSessionSyncScopeAndConflicts(t *testing.T) {
	probe := &fakeCloudProbe{st: CloudSignInState{APITokenPresent: true}}
	runner := &fakeCloudRunner{release: make(chan error, 1)}
	srv := newCloudAccountTestServer(t, probe, runner)
	t.Cleanup(func() { runner.release <- nil })
	rec := postJSON(srv.handleCloudSync, "/api/cloud/sync", `{"session_id":"chosen"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("selected sync: %d %s", rec.Code, rec.Body.String())
	}
	cloudWaitFor(t, "scoped sync spawn", func() bool { return len(runner.calls()) == 1 })
	runner.mu.Lock()
	args := append([]string(nil), runner.argvs[0]...)
	runner.mu.Unlock()
	if !reflect.DeepEqual(args, []string{"--session", "chosen"}) {
		t.Fatalf("sync must preserve selection: %v", args)
	}
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"session_id":"chosen"}`, http.StatusOK},
		{`{"session_id":"different"}`, http.StatusConflict},
		{`{}`, http.StatusConflict},
		{`{"session_id":""}`, http.StatusBadRequest},
		{`{"session_id":" "}`, http.StatusBadRequest},
		{`{"session_id":null}`, http.StatusBadRequest},
		{`{"session":"chosen"}`, http.StatusBadRequest},
		{`{"session_id":"chosen"} {}`, http.StatusBadRequest},
	} {
		rec = postJSON(srv.handleCloudSync, "/api/cloud/sync", tc.body)
		if rec.Code != tc.code {
			t.Errorf("request %s: status %d, want %d", tc.body, rec.Code, tc.code)
		}
	}
	if len(runner.calls()) != 1 {
		t.Fatal("conflicting request spawned a second sync")
	}
}
