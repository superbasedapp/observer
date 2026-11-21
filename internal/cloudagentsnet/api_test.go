package cloudagentsnet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
)

// vendorServer is an httptest TLS server standing in for every API host:
// the client's transport dials it whatever host the URL names, so the real
// host table, the URL policy and the auth headers are exercised end to end.
type vendorServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []*http.Request
}

func newVendorServer(t *testing.T, h http.HandlerFunc) (*vendorServer, *Client) {
	t.Helper()
	vs := &vendorServer{}
	vs.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vs.mu.Lock()
		vs.seen = append(vs.seen, r.Clone(context.Background()))
		vs.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(vs.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(vs.srv.Certificate())
	addr := vs.srv.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12},
	}
	return vs, New(Options{HTTP: &http.Client{Transport: tr}, Timeout: 5 * time.Second})
}

func (v *vendorServer) requests() []*http.Request {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]*http.Request(nil), v.seen...)
}

func connOf(t *testing.T, id string) cloudagents.Connector {
	t.Helper()
	c, ok := cloudagents.ConnectorByID(id)
	if !ok {
		t.Fatal(id)
	}
	return c
}

func recorded(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const testKey = "key_sk-test-0123456789"

func TestDefaultHostTableIsTheAPIRows(t *testing.T) {
	c := New(Options{})
	for _, u := range []string{
		"https://api.cursor.com/v1/agents", "https://api.devin.ai/v3/organizations/o/sessions", "https://app.all-hands.dev/api/v1/app-conversations/search",
		"https://app.warp.dev/api/v1/agent/runs", "https://api.qoder.com/api/v1/cloud/sessions", "https://api.qoder.com.cn/api/v1/cloud/sessions",
	} {
		if err := c.CheckURL(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	for _, u := range []string{
		"https://api.github.com/user", "https://cursor.com/x", "https://api2.cursor.sh/x", "https://app.devin.ai/x", "https://all-hands.dev/x",
		"https://openapi.qoder.sh/x", "https://openapi.qoder.com.cn/x", "https://qoder.com/x", "https://api.qoder.com.evil.example/x",
	} {
		if cloudagents.ClassOf(c.CheckURL(u)) != cloudagents.ErrHostNotAllowed {
			t.Errorf("%s allowed", u)
		}
	}
}

func TestCallPresentsTheKeyPerScheme(t *testing.T) {
	vs, c := newVendorServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	ctx := context.Background()
	cur := connOf(t, cloudagents.ConnectorCursorCloud)
	req, _ := cloudagents.APIIdentityRequest(cur, nil)
	if _, err := c.Call(ctx, req, testKey); err != nil {
		t.Fatal(err)
	}
	oh := connOf(t, cloudagents.ConnectorOpenHandsCloud)
	req, _ = cloudagents.APIListRequest(oh, nil, time.Time{}, time.Time{}, "")
	if _, err := c.Call(ctx, req, testKey); err != nil {
		t.Fatal(err)
	}
	seen := vs.requests()
	if len(seen) != 2 {
		t.Fatalf("requests = %d", len(seen))
	}
	if got := seen[0].Header.Get("Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte(testKey+":")) {
		t.Errorf("cursor auth = %q", got)
	}
	if seen[0].Host != "api.cursor.com" || seen[0].URL.Path != "/v1/me" {
		t.Errorf("cursor request %s %s", seen[0].Host, seen[0].URL)
	}
	if got := seen[1].Header.Get("Authorization"); got != "Bearer "+testKey {
		t.Errorf("openhands auth = %q", got)
	}
	if seen[1].Host != "app.all-hands.dev" || seen[1].URL.Query().Get("include_sub_conversations") != "true" {
		t.Errorf("openhands request %s %s", seen[1].Host, seen[1].URL)
	}
}

func TestCallRefusals(t *testing.T) {
	vs, c := newVendorServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/me":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, `{"error":"Unauthorized","message":"Invalid API key %s"}`, testKey)
		case "/v1/agents":
			http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
		default:
			w.WriteHeader(http.StatusTooManyRequests)
		}
	})
	ctx := context.Background()
	cur := connOf(t, cloudagents.ConnectorCursorCloud)
	me, _ := cloudagents.APIIdentityRequest(cur, nil)
	list, _ := cloudagents.APIListRequest(cur, nil, time.Time{}, time.Time{}, "")
	runs, _ := cloudagents.APIDetailRequest(cur, cloudagents.DetailRuns, "bc-abc")
	devin := connOf(t, cloudagents.ConnectorDevin)
	other, _ := cloudagents.APIListRequest(devin, map[string]string{cloudagents.ParamOrgID: "o"}, time.Time{}, time.Time{}, "")
	crossHost := me
	crossHost.URL = strings.Replace(me.URL, "api.cursor.com", "api.devin.ai", 1)
	wrongScheme := other
	wrongScheme.Auth = cloudagents.AuthBasicUser
	cases := []struct {
		name string
		req  cloudagents.Request
		key  string
		want cloudagents.ErrorClass
		sent bool
	}{
		{"bad key is not signed in", me, testKey, cloudagents.ErrNotSignedIn, true},
		{"redirect never followed", list, testKey, cloudagents.ErrHostNotAllowed, true},
		{"rate limit", runs, testKey, cloudagents.ErrRateLimited, true},
		{"no key", me, "", cloudagents.ErrNotSignedIn, false},
		{"key with a line break", me, "a\r\nX-Evil: 1", cloudagents.ErrInvalid, false},
		{"another row's host", crossHost, testKey, cloudagents.ErrHostNotAllowed, false},
		{"another row's scheme", wrongScheme, testKey, cloudagents.ErrInvalid, false},
		{"a CLI connector", cloudagents.Request{Connector: cloudagents.ConnectorCopilotAgent, URL: me.URL}, testKey, cloudagents.ErrInvalid, false},
		{"plain http", cloudagents.Request{Connector: cur.ID, URL: "http://api.cursor.com/v1/me", Auth: cur.Auth}, testKey, cloudagents.ErrHostNotAllowed, false},
	}
	for _, tc := range cases {
		before := len(vs.requests())
		_, err := c.Call(ctx, tc.req, tc.key)
		if cloudagents.ClassOf(err) != tc.want {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), testKey) {
			t.Errorf("%s: key leaked into the error", tc.name)
		}
		if sent := len(vs.requests()) > before; sent != tc.sent {
			t.Errorf("%s: sent=%v want %v", tc.name, sent, tc.sent)
		}
	}
	for _, r := range vs.requests() {
		if r.Host != "api.cursor.com" {
			t.Errorf("a request reached host %s", r.Host)
		}
	}
}

func TestStreamResumeAndRefusals(t *testing.T) {
	live := recorded(t, "cloudagents/cursor-cloud/stream-live.sse")
	resume := recorded(t, "cloudagents/cursor-cloud/stream-resume.sse")
	vs, c := newVendorServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/runs/run-expired/"):
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"error":"stream_expired"}`))
			return
		case strings.Contains(r.URL.Path, "/runs/run-other/"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_last_event_id"}`))
			return
		case strings.Contains(r.URL.Path, "/runs/run-json/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("X-Cursor-Stream-Retention-Seconds", "3600")
		if r.Header.Get("Last-Event-ID") == "1792264210000-13" {
			_, _ = w.Write(resume)
			return
		}
		_, _ = w.Write(live)
		if strings.Contains(r.URL.Path, "/runs/run-hang/") {
			w.(http.Flusher).Flush()
			<-r.Context().Done() // a live run: the stream stays open
		}
	})
	ctx := context.Background()
	cur := connOf(t, cloudagents.ConnectorCursorCloud)
	read := func(run, last string, window time.Duration) (*cloudagents.RunStream, cloudagents.StreamEnd, error) {
		req, err := cloudagents.APIStreamRequest(cur, "bc-abc", run, last)
		if err != nil {
			t.Fatal(err)
		}
		rs := &cloudagents.RunStream{RunID: run}
		end, err := c.Stream(ctx, req, testKey, window, func(ev cloudagents.SSEEvent) bool {
			return rs.Add(ev, time.Now())
		})
		return rs, end, err
	}
	rs, end, err := read("run-hang", "", 500*time.Millisecond)
	if err != nil || end.Reason != cloudagents.StreamEndWindow || end.RetentionSeconds != 3600 || rs.Done || len(rs.Activity) != 3 {
		t.Fatalf("live window: %+v %+v %v", rs, end, err)
	}
	rs, end, err = read("run-2", "1792264210000-13", time.Second)
	if err != nil || end.Reason != cloudagents.StreamEndDone || !rs.Done {
		t.Fatalf("resume: %+v %+v %v", rs, end, err)
	}
	seen := vs.requests()
	if got := seen[len(seen)-1].Header.Get("Last-Event-ID"); got != "1792264210000-13" {
		t.Errorf("Last-Event-ID = %q", got)
	}
	if got := seen[len(seen)-1].Header.Get("Accept"); got != cloudagents.AcceptEventStream {
		t.Errorf("Accept = %q", got)
	}
	for run, want := range map[string]cloudagents.ErrorClass{
		"run-expired": cloudagents.ErrStreamExpired,
		"run-other":   cloudagents.ErrStreamResumeRefused,
		"run-json":    cloudagents.ErrWrongShape,
	} {
		if _, _, err := read(run, "3", time.Second); cloudagents.ClassOf(err) != want {
			t.Errorf("%s: %v want %s", run, err, want)
		}
	}
	// A JSON call is never a stream and a stream is never a JSON call.
	req, _ := cloudagents.APIStreamRequest(cur, "bc-abc", "run-2", "")
	if _, err := c.Call(ctx, req, testKey); cloudagents.ClassOf(err) != cloudagents.ErrInvalid {
		t.Errorf("Call on a stream: %v", err)
	}
	me, _ := cloudagents.APIIdentityRequest(cur, nil)
	if _, err := c.Stream(ctx, me, testKey, time.Second, func(cloudagents.SSEEvent) bool { return true }); cloudagents.ClassOf(err) != cloudagents.ErrInvalid {
		t.Errorf("Stream on a JSON call: %v", err)
	}
}

// TestQoderCloudEgress (lane CA-V2): a qoder-cloud request reaches either
// region host of its row with the token as a Bearer header, never another
// row's host; another row's request never reaches a Qoder host.
func TestQoderCloudEgress(t *testing.T) {
	vs, c := newVendorServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[],"has_more":false,"next_page":null}`))
	})
	ctx := context.Background()
	q := connOf(t, cloudagents.ConnectorQoderCloud)
	for _, region := range []string{"global", "cn"} {
		req, err := cloudagents.APIListRequest(q, map[string]string{cloudagents.ParamRegion: region}, time.Time{}, time.Time{}, "")
		if err != nil {
			t.Fatal(err)
		}
		before := len(vs.requests())
		if _, err := c.Call(ctx, req, testKey); err != nil {
			t.Fatalf("%s: %v", region, err)
		}
		got := vs.requests()
		if len(got) != before+1 {
			t.Fatalf("%s: no request sent", region)
		}
		r := got[len(got)-1]
		if r.Header.Get("Authorization") != "Bearer "+testKey || r.URL.Path != "/api/v1/cloud/sessions" || r.URL.Query().Get("limit") != "100" {
			t.Fatalf("%s: request %s %v", region, r.URL, r.Header)
		}
	}
	list, _ := cloudagents.APIListRequest(q, map[string]string{cloudagents.ParamRegion: "global"}, time.Time{}, time.Time{}, "")
	toDevin := list
	toDevin.URL = strings.Replace(list.URL, "api.qoder.com", "api.devin.ai", 1)
	devin := connOf(t, cloudagents.ConnectorDevin)
	dl, _ := cloudagents.APIListRequest(devin, map[string]string{cloudagents.ParamOrgID: "o"}, time.Time{}, time.Time{}, "")
	devinToQoder := dl
	devinToQoder.URL = strings.Replace(dl.URL, "api.devin.ai", "api.qoder.com.cn", 1)
	sisterHost := list
	sisterHost.URL = strings.Replace(list.URL, "api.qoder.com", "openapi.qoder.sh", 1)
	before := len(vs.requests())
	for name, req := range map[string]cloudagents.Request{"qoder to devin": toDevin, "devin to qoder": devinToQoder, "qoder openapi host": sisterHost} {
		if _, err := c.Call(ctx, req, testKey); cloudagents.ClassOf(err) != cloudagents.ErrHostNotAllowed {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(vs.requests()) != before {
		t.Fatal("a refused request was sent")
	}
}

// TestClineAbsentStatusesAreEmptyReads (lane CA-V6): the cline-cloud row
// declares that a status or history read answering 404 or 410 means the
// record does not exist (yet). The egress returns the JSON body null for
// exactly those, keeps every other status's error class, and never lets a
// request widen what its own row declares (a forged Absent on the list
// stays permission_denied). The key goes to api.cline.bot as Bearer.
func TestClineAbsentStatusesAreEmptyReads(t *testing.T) {
	vs, c := newVendorServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/ses-none/history"), r.URL.Path == "/api/v1/session":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found, synthetic secret-ish body"}`))
		case strings.HasSuffix(r.URL.Path, "/ses-gone/status"):
			w.WriteHeader(http.StatusGone)
		case strings.HasSuffix(r.URL.Path, "/ses-boom/history"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			_, _ = w.Write([]byte(`{"version":1,"messages":[]}`))
		}
	})
	ctx := context.Background()
	cl := connOf(t, cloudagents.ConnectorClineCloud)
	hist, _ := cloudagents.APIHistoryRequest(cl, nil, "ses-none", "", time.Time{}, time.Time{})
	if b, err := c.Call(ctx, hist, testKey); err != nil || string(b) != "null" {
		t.Fatalf("404 history = %q, %v; want the JSON null", b, err)
	}
	st, _ := cloudagents.APIDetailRequest(cl, cloudagents.DetailStatus, "ses-gone")
	if b, err := c.Call(ctx, st, testKey); err != nil || string(b) != "null" {
		t.Fatalf("410 status = %q, %v; want the JSON null", b, err)
	}
	boom, _ := cloudagents.APIHistoryRequest(cl, nil, "ses-boom", "", time.Time{}, time.Time{})
	if _, err := c.Call(ctx, boom, testKey); cloudagents.ClassOf(err) != cloudagents.ErrServerError {
		t.Fatalf("500 history class = %s", cloudagents.ClassOf(err))
	}
	list, _ := cloudagents.APIListRequest(cl, nil, time.Time{}, time.Time{}, "")
	list.Absent = []int{404}
	if _, err := c.Call(ctx, list, testKey); cloudagents.ClassOf(err) != cloudagents.ErrPermissionDenied {
		t.Fatalf("a forged Absent widened the list's row: %v", err)
	}
	seen := vs.requests()
	if len(seen) != 4 {
		t.Fatalf("requests = %d", len(seen))
	}
	for _, r := range seen {
		if r.Host != "api.cline.bot" || r.Header.Get("Authorization") != "Bearer "+testKey {
			t.Errorf("request %s %s auth %q", r.Host, r.URL, r.Header.Get("Authorization"))
		}
	}
	if err := c.CheckURL("https://api.cline.bot/api/v1/session"); err != nil {
		t.Errorf("api.cline.bot refused: %v", err)
	}
	for _, u := range []string{"https://app.cline.bot/api/v1/session", "https://core-api.staging.int.cline.bot/api/v1/session"} {
		if cloudagents.ClassOf(c.CheckURL(u)) != cloudagents.ErrHostNotAllowed {
			t.Errorf("%s allowed", u)
		}
	}
}
