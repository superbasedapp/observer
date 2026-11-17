package instabox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fake_test.go is an in-memory InstaBox API built from the OpenAPI
// document's shapes (testdata/README.md): machines with metadata, create and
// delete operations, exec, file put and get, and the terminal WebSocket, on
// which it plays a login shell that runs the start script the client typed.

const fakeKey = "ibk_FAKEKEY_harness"

// knownCreateFields is CreateMachineRequest's property set (the vendor
// refuses any other key with 400 unknown_field).
var knownCreateFields = map[string]bool{
	"archiveSeconds": true, "autoSuspendAfterSeconds": true, "deleteAfterSeconds": true, "desiredState": true,
	"directSecrets": true, "env": true, "envSecrets": true, "failFast": true, "guestUser": true, "imageId": true,
	"maxRunMinutes": true, "memMiB": true, "metadata": true, "name": true, "orgId": true, "persistentDiskGiB": true,
	"pool": true, "rootDiskGiB": true, "secrets": true, "snapshotId": true, "templateId": true, "templateVersion": true,
	"vault": true, "vcpus": true,
}

type fakeFile struct {
	data []byte
	mode string
}

type fakeExec struct {
	Argv    []string          `json:"argv"`
	Cwd     string            `json:"cwd"`
	Envs    map[string]string `json:"envs"`
	Stdin   string            `json:"stdin"`
	Timeout int               `json:"timeoutSeconds"`
}

type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	machines   map[string]map[string]any
	ops        map[string]map[string]any
	files      map[string]fakeFile
	creates    []map[string]any
	createKeys []string
	execs      []fakeExec
	deletes    []http.Header
	n          int
	createFail map[string]any // a failed operation's error for the next create
	createCode int            // an HTTP refusal for the next create
	createBody string
	execResult map[string]any
	// shell is the program a start script runs: it gets the terminal's
	// input after the marker and writes its output.
	shell func(in <-chan []byte, out func([]byte), exit func(int))
	// noMarker makes the shell exit before printing the marker.
	noMarker bool
	terms    []string // terminal query strings
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, machines: map[string]map[string]any{}, ops: map[string]map[string]any{}, files: map[string]fakeFile{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Options{Endpoint: f.srv.URL, Key: fakeKey, Sleep: func(context.Context, time.Duration) error { return nil }, StartWait: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeErr(w http.ResponseWriter, status int, code string, retryable bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code": code, "message": code + " (fake " + echoKey(code) + ")", "requestId": "req", "retryable": retryable, "operationId": nil,
	}})
}

// echoKey makes the fake echo the key in one error's message (a vendor
// that repeats a header), so redaction is tested.
func echoKey(code string) string {
	if code == "echo_key" {
		return fakeKey
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// lookup finds a machine by id or name (the vendor's MachineRef).
func (f *fakeAPI) lookup(ref string) map[string]any {
	if m, ok := f.machines[ref]; ok {
		return m
	}
	for _, m := range f.machines {
		if m["name"] == ref {
			return m
		}
	}
	return nil
}

var machinePath = regexp.MustCompile(`^/v1/machines/([^/]+)(/.*)?$`)

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != fakeKey {
		writeErr(w, http.StatusUnauthorized, "invalid_key", false)
		return
	}
	if strings.Contains(r.URL.RawQuery, fakeKey) {
		f.t.Errorf("the key reached a URL: %s", r.URL)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/machines" && r.Method == http.MethodPost:
		f.create(w, r)
	case r.URL.Path == "/v1/machines" && r.Method == http.MethodGet:
		f.list(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/operations/"):
		op := f.ops[strings.TrimPrefix(r.URL.Path, "/v1/operations/")]
		if op == nil {
			writeErr(w, http.StatusNotFound, "not_found", false)
			return
		}
		if op["state"] == "queued" {
			op["state"] = "running" // the first long-poll sees progress
		} else if op["state"] == "running" {
			f.finish(op)
		}
		writeJSON(w, http.StatusOK, op)
	default:
		mm := machinePath.FindStringSubmatch(r.URL.Path)
		if mm == nil {
			writeErr(w, http.StatusNotFound, "not_found", false)
			return
		}
		m := f.lookup(mm[1])
		if m == nil {
			writeErr(w, http.StatusNotFound, "not_found", false)
			return
		}
		f.machine(w, r, m, mm[2])
	}
}

func (f *fakeAPI) create(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Idempotency-Key") == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", false)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", false)
		return
	}
	for k := range body {
		if !knownCreateFields[k] {
			writeErr(w, http.StatusBadRequest, "unknown_field", false)
			return
		}
	}
	f.creates = append(f.creates, body)
	f.createKeys = append(f.createKeys, r.Header.Get("Idempotency-Key"))
	if f.createCode != 0 {
		code := f.createCode
		f.createCode = 0
		writeErr(w, code, f.createBody, code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable)
		return
	}
	name, _ := body["name"].(string)
	if f.lookup(name) != nil {
		writeErr(w, http.StatusConflict, "bad_request", false)
		return
	}
	f.n++
	id := fmt.Sprintf("m_fake%022d", f.n)
	meta := map[string]any{}
	if md, ok := body["metadata"].(map[string]any); ok {
		meta = md
	}
	f.machines[id] = map[string]any{
		"id": id, "name": name, "state": "creating", "metadata": meta, "runtime": map[string]any{"ready": false},
		"template": map[string]any{"id": "agent-browser"}, "free": true,
		"deleteAt": time.Now().Add(time.Duration(body["deleteAfterSeconds"].(float64)) * time.Second).UTC().Format(time.RFC3339),
	}
	op := map[string]any{"id": fmt.Sprintf("op_%d", f.n), "machineId": id, "type": "create", "state": "queued", "error": nil}
	if f.createFail != nil {
		op["fail"] = f.createFail
		f.createFail = nil
	}
	f.ops[op["id"].(string)] = op
	writeJSON(w, http.StatusAccepted, op)
}

// finish ends a running operation.
func (f *fakeAPI) finish(op map[string]any) {
	m := f.machines[op["machineId"].(string)]
	if fail, ok := op["fail"].(map[string]any); ok {
		op["state"], op["error"] = "failed", fail
		delete(op, "fail")
		delete(f.machines, op["machineId"].(string))
		return
	}
	op["state"] = "succeeded"
	switch op["type"] {
	case "create":
		m["state"], m["runtime"] = "running", map[string]any{"ready": true}
		op["machine"] = m
	case "delete":
		delete(f.machines, op["machineId"].(string))
	}
}

func (f *fakeAPI) list(w http.ResponseWriter, r *http.Request) {
	terms := r.URL.Query()["metadata"]
	var out []map[string]any
	for _, m := range f.machines {
		ok := true
		for _, t := range terms {
			k, v, _ := strings.Cut(t, ":")
			if md, _ := m["metadata"].(map[string]any); md[k] != v {
				ok = false
			}
		}
		if ok {
			out = append(out, m)
		}
	}
	// One page of one, so the cursor is followed.
	page, next := out, any(nil)
	if r.URL.Query().Get("cursor") == "" && len(out) > 1 {
		page, next = out[:1], "c1"
	} else if r.URL.Query().Get("cursor") == "c1" {
		page = out[1:]
	}
	writeJSON(w, http.StatusOK, map[string]any{"machines": page, "nextCursor": next})
}

func (f *fakeAPI) machine(w http.ResponseWriter, r *http.Request, m map[string]any, rest string) {
	id := m["id"].(string)
	switch {
	case rest == "" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, m)
	case rest == "" && r.Method == http.MethodDelete:
		f.deletes = append(f.deletes, r.Header.Clone())
		if r.Header.Get("Idempotency-Key") == "" || r.Header.Get("X-Confirm-Delete") != id {
			writeErr(w, http.StatusConflict, "delete_confirmation_required", false)
			return
		}
		m["state"] = "deleting"
		f.n++
		op := map[string]any{"id": fmt.Sprintf("op_%d", f.n), "machineId": id, "type": "delete", "state": "running", "error": nil}
		f.ops[op["id"].(string)] = op
		writeJSON(w, http.StatusAccepted, op)
	case rest == "/files" && r.Method == http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		q := r.URL.Query()
		if q.Get("parents") != "true" {
			writeErr(w, http.StatusNotFound, "missing_parent", false)
			return
		}
		f.files[id+":"+q.Get("path")] = fakeFile{data: b, mode: q.Get("mode")}
		writeJSON(w, http.StatusCreated, map[string]any{"path": q.Get("path"), "size": len(b), "sha256": "x", "mode": q.Get("mode"), "created": true})
	case rest == "/files/content" && r.Method == http.MethodGet:
		ff, ok := f.files[id+":"+r.URL.Query().Get("path")]
		if !ok {
			writeErr(w, http.StatusNotFound, "not_found", false)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(ff.data)
	case rest == "/exec" && r.Method == http.MethodPost:
		var e fakeExec
		_ = json.NewDecoder(r.Body).Decode(&e)
		f.execs = append(f.execs, e)
		res := f.execResult
		if res == nil {
			res = map[string]any{"stdout": "ok\n", "stderr": "", "exitCode": 0, "timedOut": false, "truncated": false}
		}
		writeJSON(w, http.StatusOK, res)
	case rest == "/terminal" && r.Method == http.MethodGet:
		f.terms = append(f.terms, r.URL.RawQuery)
		f.mu.Unlock()
		f.terminal(w, r, id)
		f.mu.Lock()
	default:
		writeErr(w, http.StatusNotFound, "not_found", false)
	}
}

var (
	typedLine = regexp.MustCompile(`exec sh '([^']+)'\n`)
	markerFmt = regexp.MustCompile(`printf 'OBS-%s-READY\\n' '([0-9a-f]+)'`)
)

// terminal plays a login shell: a session control, a banner and a prompt,
// the echo of what is typed, then (when the typed line runs a start script
// the client uploaded) the script's marker and the program.
func (f *fakeAPI) terminal(w http.ResponseWriter, r *http.Request, id string) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := r.Context()
	_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"session","session":"`+r.URL.Query().Get("session")+`","persistent":true}`))
	_ = c.Write(ctx, websocket.MessageBinary, []byte("Linux box 6.18.60-instabox\r\nuser@box:~$ "))
	var typed []byte
	for {
		_, b, err := c.Read(ctx)
		if err != nil {
			return
		}
		typed = append(typed, b...)
		_ = c.Write(ctx, websocket.MessageBinary, bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))) // the echo
		if m := typedLine.FindSubmatch(typed); m != nil {
			f.mu.Lock()
			script, ok := f.files[id+":"+string(m[1])]
			f.mu.Unlock()
			if !ok {
				_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"exit","code":127}`))
				return
			}
			nm := markerFmt.FindSubmatch(script.data)
			if nm == nil || f.noMarker || script.mode != "0700" || !bytes.Contains(script.data, []byte("stty raw -echo")) {
				_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"exit","code":97}`))
				return
			}
			f.mu.Lock()
			dir := strings.TrimSuffix(string(m[1]), "/start.sh")
			f.files[id+":"+dir+"/err"] = fakeFile{data: []byte("relay: started\n")}
			f.mu.Unlock()
			_ = c.Write(ctx, websocket.MessageBinary, []byte("OBS-"+string(nm[1])+"-READY\n"))
			f.run(ctx, c)
			return
		}
	}
}

// run feeds the program its input and writes its output until it exits.
func (f *fakeAPI) run(ctx context.Context, c *websocket.Conn) {
	in := make(chan []byte, 64)
	exited := make(chan int, 1)
	go func() {
		defer close(in)
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			in <- b
		}
	}()
	shell := f.shell
	if shell == nil {
		shell = echoUntilBye
	}
	go shell(in, func(b []byte) { _ = c.Write(ctx, websocket.MessageBinary, b) }, func(code int) { exited <- code })
	select {
	case code := <-exited:
		_ = c.Write(ctx, websocket.MessageText, []byte(fmt.Sprintf(`{"type":"exit","code":%d}`, code)))
		_ = c.Close(websocket.StatusNormalClosure, "")
	case <-ctx.Done():
	}
}

// echoUntilBye echoes its input and exits 3 on a "bye" line.
func echoUntilBye(in <-chan []byte, out func([]byte), exit func(int)) {
	var acc []byte
	for b := range in {
		out(b)
		acc = append(acc, b...)
		if bytes.Contains(acc, []byte("bye\n")) {
			exit(3)
			return
		}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
