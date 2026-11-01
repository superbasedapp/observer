package vercel

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeVercel is an in-memory Vercel Sandbox API over httptest, answering in
// the recorded shapes (testdata) and checking what the client sends: the
// bearer token, the teamId on every call, the projectId where the spec puts
// it.
type fakeVercel struct {
	t       *testing.T
	srv     *httptest.Server
	token   string
	team    string
	project string

	mu         sync.Mutex
	boxes      map[string]*fakeBox
	cmds       map[string]*fakeCmd
	creates    []map[string]any
	nextCmd    int
	fail429    int
	fail500    int
	retryAt    string
	dropCreate bool
	// dropLogsAt cuts the first log stream after this many stdout lines.
	dropLogsAt int
	stdin504   int
	stdinPosts int
	pageSize   int
	// missingImage is an image the create answers 404 for (one the team
	// does not own).
	missingImage string
}

type fakeBox struct {
	name    string
	sid     string
	tags    map[string]string
	running bool
	files   map[string]fakeFile
}

type fakeFile struct {
	data []byte
	mode int64
}

type fakeCmd struct {
	argv   []string
	sudo   bool
	cwd    string
	env    map[string]string
	stdin  []byte
	closed bool
	chunks []string
	exit   *int
}

func newFakeVercel(t *testing.T) *fakeVercel {
	f := &fakeVercel{t: t, token: "vercel_FAKEtoken_0123456789", team: "team_FAKE", project: "prj_FAKE", boxes: map[string]*fakeBox{}, cmds: map[string]*fakeCmd{}, pageSize: 50}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVercel) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Options{Endpoint: f.srv.URL, Token: f.token, TeamID: f.team, ProjectID: f.project, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func recorded(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func vErr(w http.ResponseWriter, code int, c, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{"code": c, "message": msg}})
}

func (f *fakeVercel) hangUp(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		f.t.Fatal("no hijacker")
	}
	conn, _, _ := hj.Hijack()
	_ = conn.Close()
}

func (f *fakeVercel) boxJSON(b *fakeBox) map[string]any {
	m := recorded(f.t, "create_200.json")
	sb := m["sandbox"].(map[string]any)
	sb["name"], sb["tags"], sb["currentSessionId"] = b.name, b.tags, b.sid
	ss := m["session"].(map[string]any)
	ss["id"] = b.sid
	if !b.running {
		sb["status"], ss["status"] = "stopped", "stopped"
	}
	return m
}

func (f *fakeVercel) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token || r.URL.Query().Get("teamId") != f.team {
		// The answer echoes what it got, so a leak in the client's error
		// path would show the token.
		vErr(w, 401, "forbidden", "bad credentials "+r.Header.Get("Authorization"))
		return
	}
	f.mu.Lock()
	if f.fail429 > 0 {
		f.fail429--
		f.mu.Unlock()
		if f.retryAt != "" {
			w.Header().Set("Retry-After", f.retryAt)
		}
		writeJSON(w, 429, recorded(f.t, "error_429.json"))
		return
	}
	if f.fail500 > 0 {
		f.fail500--
		f.mu.Unlock()
		vErr(w, 502, "bad_gateway", "upstream")
		return
	}
	f.mu.Unlock()
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == "/v3/sandboxes":
		f.create(w, r)
	case r.Method == http.MethodGet && p == "/v2/sandboxes":
		f.list(w, r)
	case strings.HasPrefix(p, "/v2/sandboxes/sessions/"):
		f.session(w, r, strings.TrimPrefix(p, "/v2/sandboxes/sessions/"))
	case strings.HasPrefix(p, "/v2/sandboxes/"):
		f.named(w, r, strings.TrimPrefix(p, "/v2/sandboxes/"))
	default:
		vErr(w, 404, "not_found", "no route "+p)
	}
}

func (f *fakeVercel) create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		vErr(w, 400, "bad_request", err.Error())
		return
	}
	f.mu.Lock()
	f.creates = append(f.creates, body)
	if img, _ := body["image"].(string); img != "" && img == f.missingImage {
		f.mu.Unlock()
		vErr(w, 404, "not_found", "Image not found.")
		return
	}
	name, _ := body["name"].(string)
	if _, ok := f.boxes[name]; ok {
		f.mu.Unlock()
		vErr(w, 409, "conflict", "a sandbox with this name exists")
		return
	}
	tags := map[string]string{}
	if tm, ok := body["tags"].(map[string]any); ok {
		for k, v := range tm {
			tags[k], _ = v.(string)
		}
	}
	b := &fakeBox{name: name, sid: "sbx_" + strings.TrimPrefix(name, "observer-"), tags: tags, running: true, files: map[string]fakeFile{}}
	f.boxes[name] = b
	drop := f.dropCreate
	f.dropCreate = false
	out := f.boxJSON(b)
	f.mu.Unlock()
	if drop {
		f.hangUp(w)
		return
	}
	writeJSON(w, 200, out)
}

func (f *fakeVercel) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("project") != f.project {
		vErr(w, 400, "bad_request", "project")
		return
	}
	k, v, _ := strings.Cut(q.Get("tags"), ":")
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for n, b := range f.boxes {
		if b.tags[k] == v {
			names = append(names, n)
		}
	}
	// Stable order for the cursor.
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	start, _ := strconv.Atoi(q.Get("cursor"))
	end := min(start+f.pageSize, len(names))
	var sbs []any
	for _, n := range names[start:end] {
		sbs = append(sbs, f.boxJSON(f.boxes[n])["sandbox"])
	}
	var next any
	if end < len(names) {
		next = strconv.Itoa(end)
	}
	writeJSON(w, 200, map[string]any{"sandboxes": sbs, "pagination": map[string]any{"count": len(sbs), "next": next}})
}

func (f *fakeVercel) named(w http.ResponseWriter, r *http.Request, name string) {
	if r.URL.Query().Get("projectId") != f.project {
		vErr(w, 400, "bad_request", "projectId")
		return
	}
	f.mu.Lock()
	b, ok := f.boxes[name]
	if !ok {
		f.mu.Unlock()
		vErr(w, 404, "not_found", "sandbox not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		out := f.boxJSON(b)
		f.mu.Unlock()
		writeJSON(w, 200, out)
	case http.MethodDelete:
		if r.URL.Query().Get("deleteOrphanSnapshots") != "true" {
			f.mu.Unlock()
			vErr(w, 400, "bad_request", "snapshots")
			return
		}
		delete(f.boxes, name)
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{})
	default:
		f.mu.Unlock()
		vErr(w, 405, "method", "")
	}
}

func (f *fakeVercel) boxBySession(sid string) *fakeBox {
	for _, b := range f.boxes {
		if b.sid == sid && b.running {
			return b
		}
	}
	return nil
}

func (f *fakeVercel) session(w http.ResponseWriter, r *http.Request, rest string) {
	sid, tail, _ := strings.Cut(rest, "/")
	f.mu.Lock()
	b := f.boxBySession(sid)
	f.mu.Unlock()
	if b == nil {
		vErr(w, 410, "gone", "session stopped")
		return
	}
	switch {
	case tail == "fs/write":
		f.fsWrite(w, r, b)
	case tail == "fs/read":
		f.fsRead(w, r, b)
	case tail == "cmd":
		f.startCmd(w, r)
	case strings.HasPrefix(tail, "cmd/"):
		id, op, _ := strings.Cut(strings.TrimPrefix(tail, "cmd/"), "/")
		f.mu.Lock()
		c := f.cmds[id]
		f.mu.Unlock()
		if c == nil {
			vErr(w, 404, "not_found", "command")
			return
		}
		f.cmdOp(w, r, c, op)
	default:
		vErr(w, 404, "not_found", tail)
	}
}

func (f *fakeVercel) fsWrite(w http.ResponseWriter, r *http.Request, b *fakeBox) {
	if r.Header.Get("Content-Type") != "application/gzip" || r.Header.Get("X-Cwd") != "/" {
		vErr(w, 400, "bad_request", "content type or cwd")
		return
	}
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		vErr(w, 400, "bad_request", err.Error())
		return
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			vErr(w, 400, "bad_request", err.Error())
			return
		}
		data, _ := io.ReadAll(tr)
		f.mu.Lock()
		b.files["/"+h.Name] = fakeFile{data: data, mode: h.Mode}
		f.mu.Unlock()
	}
	writeJSON(w, 200, map[string]any{})
}

func (f *fakeVercel) fsRead(w http.ResponseWriter, r *http.Request, b *fakeBox) {
	var body struct {
		Path string `json:"path"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	file, ok := b.files[body.Path]
	f.mu.Unlock()
	if !ok {
		vErr(w, 404, "file_not_found", "no such file")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(file.data)
}

func (f *fakeVercel) startCmd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Command     string            `json:"command"`
		Args        []string          `json:"args"`
		Cwd         string            `json:"cwd"`
		Env         map[string]string `json:"env"`
		Sudo        bool              `json:"sudo"`
		AttachStdin bool              `json:"attachStdin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		vErr(w, 400, "bad_request", err.Error())
		return
	}
	c := &fakeCmd{argv: append([]string{body.Command}, body.Args...), sudo: body.Sudo, cwd: body.Cwd, env: body.Env}
	switch strings.Join(c.argv, " ") {
	case "cat":
	case "sh -c exit 3":
		c.chunks = []string{"bye\n"}
		c.exit = new(int)
		*c.exit = 3
	default:
		c.exit = new(int)
	}
	f.mu.Lock()
	f.nextCmd++
	id := "cmd_" + strconv.Itoa(f.nextCmd)
	f.cmds[id] = c
	f.mu.Unlock()
	out := recorded(f.t, "cmd_200.json")
	out["command"].(map[string]any)["id"] = id
	writeJSON(w, 200, out)
}

func (f *fakeVercel) cmdOp(w http.ResponseWriter, r *http.Request, c *fakeCmd, op string) {
	switch op {
	case "logs":
		f.logs(w, c)
	case "stdin":
		f.stdin(w, r, c)
	case "kill":
		f.mu.Lock()
		if c.exit == nil {
			c.exit = new(int)
			*c.exit = 143
		}
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"command": map[string]any{"id": "x"}})
	case "":
		deadline := time.Now().Add(5 * time.Second)
		for {
			f.mu.Lock()
			exit := c.exit
			f.mu.Unlock()
			if exit != nil || r.URL.Query().Get("wait") != "true" || time.Now().After(deadline) {
				writeJSON(w, 200, map[string]any{"command": map[string]any{"exitCode": exit}})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	default:
		vErr(w, 404, "not_found", op)
	}
}

func (f *fakeVercel) logs(w http.ResponseWriter, c *fakeCmd) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	fl := w.(http.Flusher)
	_, _ = io.WriteString(w, `{"stream":"stderr","data":"noise"}`+"\n")
	sent := 0
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		chunks := append([]string(nil), c.chunks...)
		exited := c.exit != nil
		drop := f.dropLogsAt > 0 && sent >= f.dropLogsAt
		if drop {
			f.dropLogsAt = 0
		}
		f.mu.Unlock()
		if drop {
			fl.Flush()
			f.hangUp(w)
			return
		}
		if sent < len(chunks) {
			line, _ := json.Marshal(map[string]string{"stream": "stdout", "data": chunks[sent]})
			_, _ = w.Write(append(line, '\n'))
			fl.Flush()
			sent++
			continue
		}
		if exited {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (f *fakeVercel) stdin(w http.ResponseWriter, r *http.Request, c *fakeCmd) {
	var body struct {
		Data   string `json:"data"`
		Offset int64  `json:"offset"`
		Close  bool   `json:"close"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		vErr(w, 400, "bad_request", err.Error())
		return
	}
	data, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		vErr(w, 400, "bad_request", "base64")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stdinPosts++
	if body.Offset != int64(len(c.stdin)) {
		vErr(w, 409, "conflict", fmt.Sprintf("offset %d, have %d", body.Offset, len(c.stdin)))
		return
	}
	if f.stdin504 > 0 && len(data) > 0 {
		f.stdin504--
		took := min(3, len(data))
		c.stdin = append(c.stdin, data[:took]...)
		c.chunks = append(c.chunks, string(data[:took]))
		b := recorded(f.t, "stdin_504.json")
		b["error"].(map[string]any)["bytesWritten"] = took
		writeJSON(w, 504, b)
		return
	}
	c.stdin = append(c.stdin, data...)
	if len(data) > 0 && strings.Join(c.argv, " ") == "cat" {
		c.chunks = append(c.chunks, string(data))
	}
	if body.Close {
		c.closed = true
		if c.exit == nil {
			c.exit = new(int)
		}
	}
	writeJSON(w, 200, map[string]any{"command": map[string]any{"id": "x"}, "bytesWritten": len(data)})
}
