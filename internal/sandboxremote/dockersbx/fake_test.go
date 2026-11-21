package dockersbx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fake is an httptest server speaking the shapes of Docker's Sandboxes API
// (api.yaml read 2026-11-11) and Docker Hub's exchange: the management
// plane under /sandboxes, each box's endpoint under /box/<uid>. Its fault
// switches inject what the tests need. No live call is ever made.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// exchange
	exchanges    int
	lastExchange exchangeBody
	mgmt         string
	reject401    int // management requests to answer 401 (then re-exchange)
	// grants
	grants int
	scopes map[string]string // issued value -> box uid
	// boxes
	boxes        map[string]*fakeBox
	order        []string
	creates      []createBody
	createKeys   []string
	replay       map[string]string // Idempotency-Key -> uid
	cutCreates   int               // create requests admitted and then cut
	createStatus string            // status a create answers (running default)
	pollsToRun   int               // reads before a creating box runs
	failNewBoxes bool              // a creating box goes to failed instead
	retry429     int               // creates to answer 429 with a RetryInfo delay first
	retryDelay   string
	staleEtag    int // deletes to answer 412 first
	deletes      []string
	listPage     int    // page size of the list (0: all at once)
	boxBase      string // a box endpoint base override (the host refusal)
	// processes
	procs     map[string]*fakeProc
	pseq      int
	dropAfter int // chunks sent on a stream before it is cut with 1008 (once)
	dropped   bool
	attaches  []int64
	signals   []string
	// files
	mkdirs []string
	files  map[string]fakeFile
}

type fakeBox struct {
	uid, display, status string
	labels               map[string]string
	etag                 int
	polls                int
}

type fakeFile struct {
	data []byte
	mode uint32
}

type fakeChunk struct {
	stream string
	data   []byte
	seq    int64
}

type fakeProc struct {
	uid    string
	body   createProcessBody
	chunks []fakeChunk
	exit   *int
	notify chan struct{}
	stdin  []byte
	closed bool
	sizes  []termSize
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, mgmt: "mgmt-1", scopes: map[string]string{}, boxes: map[string]*fakeBox{}, replay: map[string]string{}, procs: map[string]*fakeProc{}, files: map[string]fakeFile{}, retryDelay: "1.5s"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// client builds a client on the fake with no-op sleeps and the given
// option edits.
func (f *fake) client(t *testing.T, edit ...func(*Options)) *Client {
	t.Helper()
	o := Options{
		Endpoint: f.srv.URL + "/sandboxes", ExchangeURL: f.srv.URL + "/v2/auth/token",
		DockerID: "dev-user", Access: "dckr-fake-access-1234",
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	}
	for _, e := range edit {
		e(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeJSONResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, ecode, msg string) {
	writeJSONResp(w, code, map[string]any{"code": ecode, "message": msg})
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v2/auth/token":
		f.exchange(w, r)
	case strings.HasPrefix(r.URL.Path, "/sandboxes/v1/sandboxes"):
		if !f.mgmtOK(w, r) {
			return
		}
		f.management(w, r, strings.TrimPrefix(r.URL.Path, "/sandboxes/v1/sandboxes"))
	case strings.HasPrefix(r.URL.Path, "/box/"):
		rest := strings.TrimPrefix(r.URL.Path, "/box/")
		uid, sub, _ := strings.Cut(rest, "/")
		if !f.scopeOK(w, r, uid) {
			return
		}
		f.endpoint(w, r, uid, "/"+sub)
	default:
		writeErr(w, 404, "notFound", "no route")
	}
}

func (f *fake) exchange(w http.ResponseWriter, r *http.Request) {
	var b exchangeBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	f.mu.Lock()
	f.exchanges++
	f.lastExchange = b
	f.mgmt = "mgmt-" + strconv.Itoa(f.exchanges)
	m := f.mgmt
	f.mu.Unlock()
	if b.Identifier != "dev-user" || b.Value != "dckr-fake-access-1234" {
		writeErr(w, 401, "unauthenticated", "bad login")
		return
	}
	writeJSONResp(w, 200, exchangeAnswer{Issued: m})
}

func (f *fake) mgmtOK(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reject401 > 0 {
		f.reject401--
		f.mgmt = "expired"
	}
	if r.Header.Get("Authorization") != authorization(f.mgmt) {
		writeErr(w, 401, "unauthenticated", "expired management token")
		return false
	}
	return true
}

func (f *fake) scopeOK(w http.ResponseWriter, r *http.Request, uid string) bool {
	v := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	ok := f.scopes[v] == uid && v != ""
	f.mu.Unlock()
	if !ok {
		writeErr(w, 401, "unauthenticated", "scoped credential missing or expired")
	}
	return ok
}

// expireScopes makes every issued endpoint grant invalid (as an expiry).
func (f *fake) expireScopes() {
	f.mu.Lock()
	f.scopes = map[string]string{}
	f.mu.Unlock()
}

func (f *fake) view(b *fakeBox) map[string]any {
	core := map[string]any{"status": b.status, "labels": b.labels, "etag": `"v` + strconv.Itoa(b.etag) + `"`, "createdAt": "2026-11-11T10:00:00Z"}
	base := f.srv.URL + "/box/" + b.uid
	if f.boxBase != "" {
		base = f.boxBase + "/box/" + b.uid
	}
	core["endpoint"] = map[string]any{"uri": base, "protocol": "http", "sandbox": "sandboxes/" + b.uid, "sandboxUid": b.uid, "apiVersion": "v1"}
	return map[string]any{
		"name": "sandboxes/" + b.uid, "uid": b.uid, "displayName": b.display, "core": core,
		"effectiveFeatures": map[string]any{"timeouts": map[string]any{"onTimeout": "delete", "initialTimeout": "600s", "expiresAt": "2026-11-11T11:00:00Z"}},
	}
}

func (f *fake) management(w http.ResponseWriter, r *http.Request, rest string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case rest == "" && r.Method == http.MethodPost:
		var body createBody
		raw, _ := io.ReadAll(r.Body)
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeErr(w, 400, "invalidArgument", err.Error())
			return
		}
		if f.retry429 > 0 {
			f.retry429--
			writeJSONResp(w, 429, map[string]any{"code": "resourceExhausted", "message": "slow down", "details": []map[string]any{{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": f.retryDelay}}})
			return
		}
		idem := r.Header.Get("Idempotency-Key")
		f.creates = append(f.creates, body)
		f.createKeys = append(f.createKeys, idem)
		if body.ImageRef == "missing/image:1" {
			writeErr(w, 400, "invalidArgument", "image_ref: not found")
			return
		}
		uid, seen := f.replay[idem]
		if !seen {
			f.pseq++
			uid = "sbx" + strconv.Itoa(f.pseq)
			st := f.createStatus
			if st == "" {
				st = "running"
			}
			f.boxes[uid] = &fakeBox{uid: uid, display: body.DisplayName, status: st, labels: body.Labels, etag: 1}
			f.order = append(f.order, uid)
			f.replay[idem] = uid
		}
		if f.cutCreates > 0 {
			f.cutCreates--
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		code := 201
		if f.boxes[uid].status != "running" {
			code = 202
		}
		w.Header().Set("ETag", `"v`+strconv.Itoa(f.boxes[uid].etag)+`"`)
		writeJSONResp(w, code, f.view(f.boxes[uid]))
	case rest == "" && r.Method == http.MethodGet:
		start, _ := strconv.Atoi(r.URL.Query().Get("pageToken"))
		var page []map[string]any
		next := ""
		for i := start; i < len(f.order); i++ {
			if f.listPage > 0 && len(page) == f.listPage {
				next = strconv.Itoa(i)
				break
			}
			if b := f.boxes[f.order[i]]; b != nil {
				page = append(page, f.view(b))
			}
		}
		writeJSONResp(w, 200, map[string]any{"sandboxes": page, "nextPageToken": next})
	default:
		uid, sub, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
		b := f.boxes[uid]
		if b == nil {
			writeErr(w, 404, "notFound", "The target is absent or not visible within the caller's scope.")
			return
		}
		switch {
		case sub == "" && r.Method == http.MethodGet:
			if b.status == "creating" {
				b.polls++
				if b.polls >= f.pollsToRun {
					b.status = "running"
					if f.failNewBoxes {
						b.status = "failed"
					}
					b.etag++
				}
			}
			w.Header().Set("ETag", `"v`+strconv.Itoa(b.etag)+`"`)
			v := f.view(b)
			if b.status == "failed" {
				v["failure"] = map[string]any{"code": "notFound", "message": "image pull failed"}
			}
			writeJSONResp(w, 200, v)
		case sub == "" && r.Method == http.MethodDelete:
			f.deletes = append(f.deletes, r.Header.Get("If-Match"))
			if r.URL.Query().Get("force") != "true" {
				writeErr(w, 400, "invalidArgument", "force expected by the fake")
				return
			}
			if f.staleEtag > 0 {
				f.staleEtag--
				b.etag++
				writeErr(w, 412, "failedPrecondition", "etag_mismatch")
				return
			}
			if r.Header.Get("If-Match") != `"v`+strconv.Itoa(b.etag)+`"` {
				writeErr(w, 412, "failedPrecondition", "etag_mismatch")
				return
			}
			delete(f.boxes, uid)
			w.WriteHeader(204)
		case sub == "endpoint-credentials" && r.Method == http.MethodPost:
			var gr grantRequest
			_ = json.NewDecoder(r.Body).Decode(&gr)
			if len(gr.Permissions) != 3 || gr.TTL != "300s" {
				writeErr(w, 400, "invalidArgument", "unexpected grant request")
				return
			}
			f.grants++
			v := "scope-" + uid + "-" + strconv.Itoa(f.grants)
			f.scopes[v] = uid
			w.Header().Set("Cache-Control", "no-store")
			writeJSONResp(w, 200, grantAnswer{Issued: v, ExpireTime: "2026-11-11T10:05:00Z"})
		default:
			writeErr(w, 404, "notFound", "no route")
		}
	}
}

func (f *fake) endpoint(w http.ResponseWriter, r *http.Request, uid, sub string) {
	switch {
	case sub == "/v1/processes" && r.Method == http.MethodPost:
		var body createProcessBody
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeErr(w, 400, "invalidArgument", err.Error())
			return
		}
		f.mu.Lock()
		f.pseq++
		p := &fakeProc{uid: "p" + strconv.Itoa(f.pseq), body: body, notify: make(chan struct{})}
		f.procs[p.uid] = p
		f.start(p)
		f.mu.Unlock()
		writeJSONResp(w, 201, map[string]any{"name": "processes/" + p.uid, "uid": p.uid, "state": "running", "label": p.uid, "receiptKind": "fresh"})
	case strings.HasPrefix(sub, "/v1/processes/"):
		pid, action, _ := strings.Cut(strings.TrimPrefix(sub, "/v1/processes/"), "/")
		f.mu.Lock()
		p := f.procs[pid]
		f.mu.Unlock()
		if p == nil {
			writeErr(w, 404, "notFound", "no process")
			return
		}
		switch action {
		case "interact":
			f.interact(w, r, p)
		case "signal":
			var s struct {
				Signal string `json:"signal"`
			}
			_ = json.NewDecoder(r.Body).Decode(&s)
			f.mu.Lock()
			f.signals = append(f.signals, s.Signal)
			if s.Signal == "kill" {
				f.exit(p, 137)
			}
			f.mu.Unlock()
			writeJSONResp(w, 200, map[string]any{})
		case "":
			f.mu.Lock()
			v := map[string]any{"name": "processes/" + p.uid, "uid": p.uid, "state": "running", "label": p.uid, "lastStreamSequence": strconv.Itoa(len(p.chunks))}
			if p.exit != nil {
				v["state"], v["exitCode"] = "exited", *p.exit
			}
			f.mu.Unlock()
			writeJSONResp(w, 200, v)
		}
	case sub == "/v1/files/directories" && r.Method == http.MethodPut:
		var d struct {
			Path    string `json:"path"`
			Parents bool   `json:"parents"`
		}
		_ = json.NewDecoder(r.Body).Decode(&d)
		f.mu.Lock()
		f.mkdirs = append(f.mkdirs, d.Path)
		f.mu.Unlock()
		writeJSONResp(w, 200, map[string]any{})
	case sub == "/v1/files/upload" && r.Method == http.MethodPost:
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			writeErr(w, 400, "invalidArgument", "not multipart")
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		n := 0
		var cur struct {
			Path string `json:"path"`
			Mode uint32 `json:"mode"`
		}
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				writeErr(w, 400, "invalidArgument", "truncated upload")
				return
			}
			b, _ := io.ReadAll(part)
			switch part.FormName() {
			case "metadata":
				_ = json.Unmarshal(b, &cur)
			case "content":
				f.mu.Lock()
				f.files[cur.Path] = fakeFile{data: b, mode: cur.Mode}
				f.mu.Unlock()
				n++
			}
		}
		writeJSONResp(w, 200, map[string]any{"filesWritten": n})
	case sub == "/v1/files/content" && r.Method == http.MethodGet:
		f.mu.Lock()
		ff, ok := f.files[r.URL.Query().Get("path")]
		f.mu.Unlock()
		if !ok {
			writeErr(w, 404, "notFound", "no file")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(ff.data)))
		_, _ = w.Write(ff.data)
	default:
		writeErr(w, 404, "notFound", "no route")
	}
}

// emit appends one output chunk (f.mu held).
func (f *fake) emit(p *fakeProc, stream, data string) {
	p.chunks = append(p.chunks, fakeChunk{stream: stream, data: []byte(data), seq: int64(len(p.chunks) + 1)})
	close(p.notify)
	p.notify = make(chan struct{})
}

// exit ends a process (f.mu held).
func (f *fake) exit(p *fakeProc, code int) {
	if p.exit != nil {
		return
	}
	p.exit = &code
	close(p.notify)
	p.notify = make(chan struct{})
}

// start simulates the commands the tests run (f.mu held).
func (f *fake) start(p *fakeProc) {
	stream := "stdout"
	if p.body.PTY != nil {
		stream = "pty"
	}
	switch p.body.Cmd[0] {
	case "echo":
		f.emit(p, stream, strings.Join(p.body.Cmd[1:], " ")+"\n")
		f.exit(p, 0)
	case "fail":
		f.emit(p, "stderr", "oops\n")
		f.emit(p, stream, "out\n")
		f.exit(p, 3)
	case "multi":
		for _, s := range []string{"a", "b", "c", "d"} {
			f.emit(p, stream, s)
		}
		f.exit(p, 0)
	case "env":
		f.emit(p, stream, p.body.Env["HOME"]+"|"+p.body.Env["BASE"]+"|"+p.body.User+"|"+p.body.WorkingDir)
		f.exit(p, 0)
	}
}

// interact serves one WebSocket stream of a process.
func (f *fake) interact(w http.ResponseWriter, r *http.Request, p *fakeProc) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{subprotocol}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx := r.Context()
	_, data, err := conn.Read(ctx)
	if err != nil {
		return
	}
	var a attachFrame
	if json.Unmarshal(data, &a) != nil || a.Attach.Name != "processes/"+p.uid {
		_ = conn.Close(websocket.StatusPolicyViolation, "bad attach")
		return
	}
	f.mu.Lock()
	f.attaches = append(f.attaches, a.Attach.ResumeFrom)
	f.mu.Unlock()
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var in struct {
				Stdin      []byte    `json:"stdin"`
				CloseStdin bool      `json:"closeStdin"`
				Resize     *termSize `json:"resize"`
			}
			if json.Unmarshal(data, &in) != nil {
				continue
			}
			f.mu.Lock()
			switch {
			case in.Resize != nil:
				p.sizes = append(p.sizes, *in.Resize)
			case in.CloseStdin:
				p.closed = true
				if p.body.Cmd[0] == "cat" {
					f.exit(p, 0)
				}
			case in.Stdin != nil:
				p.stdin = append(p.stdin, in.Stdin...)
				switch p.body.Cmd[0] {
				case "cat":
					f.emit(p, "stdout", string(in.Stdin))
				case "sh":
					f.emit(p, "pty", "> "+string(in.Stdin))
				}
			}
			f.mu.Unlock()
		}
	}()
	sent, n := a.Attach.ResumeFrom, 0
	for {
		f.mu.Lock()
		var pending []fakeChunk
		for _, c := range p.chunks {
			if c.seq > sent {
				pending = append(pending, c)
			}
		}
		exit, notify := p.exit, p.notify
		f.mu.Unlock()
		for _, c := range pending {
			frame := map[string]any{"chunk": map[string]any{"stream": c.stream, "data": c.data, "streamSequence": strconv.FormatInt(c.seq, 10)}}
			b, _ := json.Marshal(frame)
			if conn.Write(ctx, websocket.MessageText, b) != nil {
				return
			}
			sent = c.seq
			n++
			f.mu.Lock()
			cut := f.dropAfter > 0 && !f.dropped && n == f.dropAfter
			if cut {
				f.dropped = true
				f.scopes = map[string]string{} // the cut is an expiry: old grants no longer work
			}
			f.mu.Unlock()
			if cut {
				b, _ := json.Marshal(map[string]any{"code": "unauthenticated", "message": "endpoint credential expired"})
				_ = conn.Write(ctx, websocket.MessageText, b)
				_ = conn.Close(websocket.StatusPolicyViolation, "credential expired")
				return
			}
		}
		if exit != nil && len(pending) == 0 {
			b, _ := json.Marshal(map[string]any{"exited": map[string]any{"exitCode": *exit}})
			_ = conn.Write(ctx, websocket.MessageText, b)
			_ = conn.Close(websocket.StatusNormalClosure, "")
			return
		}
		if len(pending) > 0 {
			continue
		}
		select {
		case <-notify:
		case <-ctx.Done():
			return
		case <-readerDone:
			return
		case <-time.After(5 * time.Second):
			if conn.Write(ctx, websocket.MessageText, []byte(`{"heartbeat":{}}`)) != nil {
				return
			}
		}
	}
}
