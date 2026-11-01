package e2b

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeE2B is an httptest server playing E2B's control plane and envd from
// the public spec: stateful boxes, files and processes, with knobs that
// inject a 429, a 5xx, a dropped process stream and a lost create
// response.
type fakeE2B struct {
	t   *testing.T
	srv *httptest.Server
	key string

	mu         sync.Mutex
	n          int
	boxes      map[string]*fakeSandbox
	fail429    int
	fail503    int
	noRetry503 bool
	loseCreate bool
	dropAfter  int // drop the next process stream after this many output frames
	lastCreate map[string]any
	seenIdem   []string
	authUser   []string
}

type fakeSandbox struct {
	id       string
	token    string
	metadata map[string]string
	files    map[string][]byte
	procs    map[uint32]*fakeProc
	nextPID  uint32
}

type fakeProc struct {
	pty bool
	// input is the newest attached stream's channel: a reattach takes the
	// process's input over from a dropped stream.
	input chan []byte
	size  [2]uint16
}

func newFakeE2B(t *testing.T) *fakeE2B {
	f := &fakeE2B{t: t, key: "e2b_FAKEKEY_abcdef123456", boxes: map[string]*fakeSandbox{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeE2B) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Options{Endpoint: f.srv.URL, APIKey: f.key, EnvdURL: f.srv.URL, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err == nil {
		return c
	}
	t.Fatal(err)
	return nil
}

func (f *fakeE2B) writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"code":%d,"message":%q}`, code, msg)
}

func (f *fakeE2B) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/process.Process/") || r.URL.Path == "/files" {
		f.serveEnvd(w, r)
		return
	}
	if r.Header.Get("X-API-Key") != f.key {
		// The answer echoes what it got, so a leak in the client's error
		// path would show the key.
		f.writeErr(w, 401, "invalid key "+r.Header.Get("X-API-Key"))
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail429 > 0 {
		f.fail429--
		w.Header().Set("Retry-After", "0")
		f.writeErr(w, 429, "rate limited for "+f.key)
		return
	}
	if f.fail503 > 0 {
		f.fail503--
		if f.noRetry503 {
			w.Header().Set("Should-Retry", "false")
		}
		f.writeErr(w, 503, "unavailable")
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v2/sandboxes":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.lastCreate = body
		f.seenIdem = append(f.seenIdem, r.Header.Get("Idempotency-Key"))
		f.n++
		sb := &fakeSandbox{id: fmt.Sprintf("sbx%d", f.n), token: fmt.Sprintf("envdtok%d", f.n), files: map[string][]byte{}, procs: map[uint32]*fakeProc{}, nextPID: 100}
		if md, ok := body["metadata"].(map[string]any); ok {
			sb.metadata = map[string]string{}
			for k, v := range md {
				sb.metadata[k], _ = v.(string)
			}
		}
		f.boxes[sb.id] = sb
		if f.loseCreate {
			f.loseCreate = false
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"sandboxID": sb.id, "templateID": body["templateID"], "clientID": "x", "envdVersion": "0.2.4", "envdAccessToken": sb.token, "domain": nil})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/sandboxes/"):
		sb, ok := f.boxes[strings.TrimPrefix(r.URL.Path, "/sandboxes/")]
		if !ok {
			f.writeErr(w, 404, "not found")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sandboxID": sb.id, "state": "running", "envdAccessToken": sb.token, "metadata": sb.metadata, "endAt": "2026-10-22T13:00:00Z"})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/sandboxes/"):
		id := strings.TrimPrefix(r.URL.Path, "/sandboxes/")
		if _, ok := f.boxes[id]; !ok {
			f.writeErr(w, 404, "not found")
			return
		}
		delete(f.boxes, id)
		w.WriteHeader(204)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/sandboxes":
		k, v, _ := strings.Cut(r.URL.Query().Get("metadata"), "=")
		var out []map[string]any
		for _, sb := range f.boxes {
			if sb.metadata[k] == v {
				out = append(out, map[string]any{"sandboxID": sb.id, "state": "running", "metadata": sb.metadata})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	default:
		f.writeErr(w, 404, "no route "+r.URL.Path)
	}
}

func (f *fakeE2B) box(r *http.Request) *fakeSandbox {
	f.mu.Lock()
	defer f.mu.Unlock()
	sb := f.boxes[r.Header.Get("E2b-Sandbox-Id")]
	if sb == nil || r.Header.Get("X-Access-Token") != sb.token || r.Header.Get("E2b-Sandbox-Port") != "49983" {
		return nil
	}
	if user, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")); err == nil {
		f.authUser = append(f.authUser, strings.TrimSuffix(string(user), ":"))
	}
	return sb
}

func frame(flag byte, v any) []byte {
	b, _ := json.Marshal(v)
	out := make([]byte, 5+len(b))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:], uint32(len(b)))
	copy(out[5:], b)
	return out
}

func (f *fakeE2B) serveEnvd(w http.ResponseWriter, r *http.Request) {
	sb := f.box(r)
	if sb == nil {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"code":401,"message":"unauthorized access"}`)
		return
	}
	switch r.URL.Path {
	case "/files":
		p := r.URL.Query().Get("path")
		if r.Method == http.MethodPost {
			file, _, err := r.FormFile("file")
			if err != nil {
				w.WriteHeader(400)
				return
			}
			b, _ := io.ReadAll(file)
			f.mu.Lock()
			sb.files[p] = b
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode([]map[string]any{{"path": p, "name": p, "type": "file"}})
			return
		}
		f.mu.Lock()
		b, ok := sb.files[p]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"message":"file not found","code":404}`)
			return
		}
		_, _ = w.Write(b)
	case "/process.Process/Start", "/process.Process/Connect":
		if r.Header.Get("Content-Type") != "application/connect+json" || r.Header.Get("Connect-Protocol-Version") != "1" {
			w.WriteHeader(415)
			return
		}
		br := bufio.NewReader(r.Body)
		var h [5]byte
		_, _ = io.ReadFull(br, h[:])
		body := make([]byte, binary.BigEndian.Uint32(h[1:]))
		_, _ = io.ReadFull(br, body)
		var req struct {
			Process struct {
				Cmd string `json:"cmd"`
				PID uint32 `json:"pid"`
			} `json:"process"`
			PTY *struct {
				Size struct{ Cols, Rows uint16 } `json:"size"`
			} `json:"pty"`
		}
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		var pid uint32
		var p *fakeProc
		if r.URL.Path == "/process.Process/Start" {
			sb.nextPID++
			pid = sb.nextPID
			p = &fakeProc{pty: req.PTY != nil, input: make(chan []byte, 16)}
			if req.PTY != nil {
				p.size = [2]uint16{req.PTY.Size.Rows, req.PTY.Size.Cols}
			}
			sb.procs[pid] = p
		} else {
			pid = req.Process.PID
			p = sb.procs[pid]
		}
		drop := f.dropAfter
		f.dropAfter = 0
		var mine chan []byte
		if p != nil {
			mine = make(chan []byte, 16)
			p.input = mine
		}
		f.mu.Unlock()
		if p == nil {
			_, _ = w.Write(frame(flagEndStream, map[string]any{"error": map[string]string{"code": "not_found", "message": "process not found"}}))
			return
		}
		w.Header().Set("Content-Type", "application/connect+json")
		fl := w.(http.Flusher)
		_, _ = w.Write(frame(flagData, map[string]any{"event": map[string]any{"start": map[string]any{"pid": pid}}}))
		fl.Flush()
		if req.Process.Cmd == "warn" {
			// One stderr line, then a clean end (the stderr sink test).
			_, _ = w.Write(frame(flagData, map[string]any{"event": map[string]any{"data": map[string]any{"stderr": base64.StdEncoding.EncodeToString([]byte("relay: refused\n"))}}}))
			_, _ = w.Write(frame(flagData, map[string]any{"event": map[string]any{"end": map[string]any{"exitCode": 0, "exited": true}}}))
			_, _ = w.Write(frame(flagEndStream, map[string]any{}))
			return
		}
		if req.Process.Cmd == "true" {
			_, _ = w.Write(frame(flagData, map[string]any{"event": map[string]any{"end": map[string]any{"exitCode": 0, "exited": true}}}))
			_, _ = w.Write(frame(flagEndStream, map[string]any{}))
			return
		}
		sent := 0
		for {
			var in []byte
			select {
			case <-r.Context().Done():
				return
			case in = <-mine:
			}
			key := "stdout"
			if p.pty {
				key = "pty"
			}
			if strings.TrimSpace(string(in)) == "exit" {
				_, _ = w.Write(frame(flagData, map[string]any{"event": map[string]any{"end": map[string]any{"exitCode": 3, "exited": true}}}))
				_, _ = w.Write(frame(flagEndStream, map[string]any{}))
				fl.Flush()
				return
			}
			_, _ = w.Write(frame(flagData, map[string]any{"event": map[string]any{"data": map[string]any{key: base64.StdEncoding.EncodeToString(in)}}}))
			fl.Flush()
			sent++
			if drop > 0 && sent >= drop {
				hj, _ := w.(http.Hijacker)
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
				return
			}
		}
	case "/process.Process/SendInput", "/process.Process/Update", "/process.Process/SendSignal":
		var req struct {
			Process struct {
				PID uint32 `json:"pid"`
			} `json:"process"`
			Input map[string]string `json:"input"`
			PTY   *struct {
				Size struct{ Cols, Rows uint16 } `json:"size"`
			} `json:"pty"`
			Signal string `json:"signal"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		p := sb.procs[req.Process.PID]
		f.mu.Unlock()
		if p == nil {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"code":"not_found","message":"process not found"}`)
			return
		}
		switch r.URL.Path {
		case "/process.Process/SendInput":
			raw := req.Input["stdin"]
			if p.pty {
				raw = req.Input["pty"]
			}
			b, _ := base64.StdEncoding.DecodeString(raw)
			f.mu.Lock()
			ch := p.input
			f.mu.Unlock()
			ch <- b
		case "/process.Process/Update":
			f.mu.Lock()
			p.size = [2]uint16{req.PTY.Size.Rows, req.PTY.Size.Cols}
			f.mu.Unlock()
		case "/process.Process/SendSignal":
			f.mu.Lock()
			ch := p.input
			f.mu.Unlock()
			ch <- []byte("exit")
		}
		_, _ = io.WriteString(w, "{}")
	}
}
