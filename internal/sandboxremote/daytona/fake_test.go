package daytona

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeDaytona is an in-memory Daytona API over httptest (the main API under
// the server root, the toolbox under /toolbox/{id}) plus an in-process SSH
// gateway reached through Options.DialSSH, answering in the recorded shapes
// (testdata) and checking what the client sends: the bearer key on every
// HTTP call, the token as the SSH user and password.
type fakeDaytona struct {
	t   *testing.T
	srv *httptest.Server
	key string

	mu          sync.Mutex
	boxes       map[string]*fakeBox
	creates     []map[string]any
	nextID      int
	fail429     int
	fail500     int
	retryAt     string
	dropCreate  bool
	pageSize    int
	missingSnap string
	createState string
	tokens      []string
	sshAddrs    []string
	execs       []string
	// echoToken makes the API echo the key in an error body.
	echoToken bool
	// sshHost is the host the ssh access answer names (default 127.0.0.1).
	sshHost string

	hostKey ssh.Signer
	// exec runs one command on the fake gateway (nil: exit 0, no output).
	exec func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int
}

type fakeBox struct {
	id, name  string
	labels    map[string]string
	state     string
	target    string
	files     map[string][]byte
	modes     map[string]string
	destroyed bool
}

func newFakeDaytona(t *testing.T) *fakeDaytona {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDaytona{t: t, key: "dtn_FAKEKEY_0123456789abcdef", boxes: map[string]*fakeBox{}, pageSize: 100, hostKey: signer, createState: "started", sshHost: "127.0.0.1"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeDaytona) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Options{
		Endpoint: f.srv.URL, Key: f.key,
		Sleep:   func(context.Context, time.Duration) error { return nil },
		DialSSH: f.dialSSH,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// recorded reads a testdata answer.
func recorded(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return m
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// dErr answers a toolbox-shaped ErrorResponse.
func dErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"statusCode": code, "message": msg, "path": "/", "timestamp": "2026-11-11T00:00:00Z"})
}

func (f *fakeDaytona) boxJSON(b *fakeBox) map[string]any {
	m := recorded(f.t, "sandbox_200.json")
	m["id"], m["name"], m["labels"], m["state"], m["target"] = b.id, b.name, b.labels, b.state, b.target
	m["toolboxProxyUrl"] = f.srv.URL + "/toolbox"
	return m
}

func (f *fakeDaytona) find(idOrName string) *fakeBox {
	if b, ok := f.boxes[idOrName]; ok {
		return b
	}
	for _, b := range f.boxes {
		if b.name == idOrName {
			return b
		}
	}
	return nil
}

func (f *fakeDaytona) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.key {
		dErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail429 > 0 {
		f.fail429--
		if f.retryAt != "" {
			w.Header().Set("Retry-After", f.retryAt)
		}
		dErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if f.fail500 > 0 {
		f.fail500--
		dErr(w, http.StatusInternalServerError, "internal")
		return
	}
	if f.echoToken {
		dErr(w, http.StatusBadRequest, "bad key "+f.key)
		return
	}
	p := r.URL.Path
	switch {
	case p == "/sandbox" && r.Method == http.MethodPost:
		f.create(w, r)
	case p == "/sandbox" && r.Method == http.MethodGet:
		f.list(w, r)
	case strings.HasPrefix(p, "/sandbox/") && strings.HasSuffix(p, "/ssh-access") && r.Method == http.MethodPost:
		f.sshAccess(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/sandbox/"), "/ssh-access"))
	case strings.HasPrefix(p, "/sandbox/"):
		f.named(w, r, strings.TrimPrefix(p, "/sandbox/"))
	case strings.HasPrefix(p, "/toolbox/"):
		f.toolbox(w, r, strings.TrimPrefix(p, "/toolbox/"))
	default:
		dErr(w, http.StatusNotFound, "no route "+p)
	}
}

func (f *fakeDaytona) create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		dErr(w, http.StatusBadRequest, err.Error())
		return
	}
	f.creates = append(f.creates, body)
	name, _ := body["name"].(string)
	if snap, _ := body["snapshot"].(string); snap != "" && snap == f.missingSnap {
		dErr(w, http.StatusNotFound, "Snapshot "+snap+" not found")
		return
	}
	if b := f.find(name); b != nil && !b.destroyed {
		dErr(w, http.StatusConflict, "Sandbox with name "+name+" already exists")
		return
	}
	labels := map[string]string{}
	if l, ok := body["labels"].(map[string]any); ok {
		for k, v := range l {
			labels[k], _ = v.(string)
		}
	}
	target, _ := body["target"].(string)
	if target == "" {
		target = "us"
	}
	f.nextID++
	b := &fakeBox{id: "sbx-" + strconv.Itoa(f.nextID), name: name, labels: labels, state: f.createState, target: target, files: map[string][]byte{}, modes: map[string]string{}}
	f.boxes[b.id] = b
	if f.dropCreate {
		f.dropCreate = false
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
		return
	}
	writeJSON(w, http.StatusOK, f.boxJSON(b))
}

func (f *fakeDaytona) list(w http.ResponseWriter, r *http.Request) {
	var want map[string]string
	if err := json.Unmarshal([]byte(r.URL.Query().Get("labels")), &want); err != nil {
		dErr(w, http.StatusBadRequest, "labels must be JSON")
		return
	}
	var match []*fakeBox
	for i := 1; i <= f.nextID; i++ {
		b := f.boxes["sbx-"+strconv.Itoa(i)]
		if b == nil {
			continue
		}
		ok := true
		for k, v := range want {
			if b.labels[k] != v {
				ok = false
			}
		}
		if ok {
			match = append(match, b)
		}
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
	end := min(start+f.pageSize, len(match))
	items := []map[string]any{}
	for _, b := range match[start:end] {
		items = append(items, f.boxJSON(b))
	}
	next := ""
	if end < len(match) {
		next = strconv.Itoa(end)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

func (f *fakeDaytona) named(w http.ResponseWriter, r *http.Request, id string) {
	b := f.find(id)
	if b == nil {
		dErr(w, http.StatusNotFound, "Sandbox "+id+" not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, f.boxJSON(b))
	case http.MethodDelete:
		b.destroyed, b.state = true, "destroyed"
		writeJSON(w, http.StatusOK, f.boxJSON(b))
	default:
		dErr(w, http.StatusMethodNotAllowed, r.Method)
	}
}

func (f *fakeDaytona) sshAccess(w http.ResponseWriter, r *http.Request, id string) {
	b := f.find(id)
	if b == nil || b.destroyed {
		dErr(w, http.StatusNotFound, "Sandbox "+id+" not found")
		return
	}
	m := recorded(f.t, "ssh_access_200.json")
	tok := fmt.Sprintf("tok%dFAKE%s", len(f.tokens), r.URL.Query().Get("expiresInMinutes"))
	f.tokens = append(f.tokens, tok)
	m["token"], m["sandboxId"] = tok, b.id
	m["sshCommand"] = "ssh -p 22 " + tok + "@" + f.sshHost
	writeJSON(w, http.StatusOK, m)
}

func (f *fakeDaytona) toolbox(w http.ResponseWriter, r *http.Request, rest string) {
	id, op, _ := strings.Cut(rest, "/")
	b := f.find(id)
	if b == nil || b.destroyed || b.id != id {
		dErr(w, http.StatusNotFound, "no sandbox")
		return
	}
	p := r.URL.Query().Get("path")
	switch {
	case op == "files/upload-v2" && r.Method == http.MethodPost:
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			dErr(w, http.StatusBadRequest, "content type")
			return
		}
		data, _ := io.ReadAll(r.Body)
		b.files[p] = data
		writeJSON(w, http.StatusOK, map[string]any{"name": filepath.Base(p), "path": p, "type": "file"})
	case op == "files/permissions" && r.Method == http.MethodPost:
		if _, ok := b.files[p]; !ok {
			dErr(w, http.StatusNotFound, "no file")
			return
		}
		b.modes[p] = r.URL.Query().Get("mode")
		w.WriteHeader(http.StatusOK)
	case op == "files/download" && r.Method == http.MethodGet:
		data, ok := b.files[p]
		if !ok {
			dErr(w, http.StatusNotFound, "no file")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	default:
		dErr(w, http.StatusNotFound, "no toolbox route "+op)
	}
}

// dialSSH is Options.DialSSH: a loopback TCP connection to an in-process
// SSH gateway (a net.Pipe would deadlock: both ends write their version
// line first).
func (f *fakeDaytona) dialSSH(ctx context.Context, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.sshAddrs = append(f.sshAddrs, addr)
	f.mu.Unlock()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		defer ln.Close()
		srv, err := ln.Accept()
		if err != nil {
			return
		}
		f.serveSSH(srv)
	}()
	var d net.Dialer
	return d.DialContext(ctx, "tcp", ln.Addr().String())
}

func (f *fakeDaytona) serveSSH(raw net.Conn) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, tok := range f.tokens {
				if meta.User() == tok && string(pass) == tok {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("bad token")
		},
	}
	cfg.AddHostKey(f.hostKey)
	conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go f.session(ch, creqs)
	}
}

func (f *fakeDaytona) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		f.mu.Lock()
		f.execs = append(f.execs, payload.Command)
		run := f.exec
		f.mu.Unlock()
		code := 0
		if run != nil {
			code = run(payload.Command, ch, ch, ch.Stderr())
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		return
	}
}
