package osvnet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const zlibCommit = "cacf7f1d4e3d44d871b605da3b647f07d718623f"

// capturingTransport answers every request from pages (by page token) and
// records what was sent; it never reaches a network.
type capturingTransport struct {
	mu     sync.Mutex
	bodies [][]byte
	urls   []string
	agents []string
	pages  map[string]string
	status int
}

func (c *capturingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.bodies = append(c.bodies, b)
	c.urls = append(c.urls, r.Method+" "+r.URL.String())
	c.agents = append(c.agents, r.Header.Get("User-Agent"))
	c.mu.Unlock()
	var q struct {
		PageToken string `json:"page_token"`
	}
	_ = json.Unmarshal(b, &q)
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(c.pages[q.PageToken])), Header: http.Header{}, Request: r}, nil
}

// TestQueryCommitSendsOnlyTheCommit: the request is one POST to
// api.osv.dev/v1/query whose body is exactly {"commit": <id>} (a further
// page adds only OSV's page token), and the answer's records come back
// with their aliases and severity label.
func TestQueryCommitSendsOnlyTheCommit(t *testing.T) {
	tr := &capturingTransport{pages: map[string]string{
		"":      `{"vulns":[{"id":"CVE-2018-25032","aliases":["GHSA-jc36-42cf-vqwj"],"database_specific":{"severity":"HIGH"},"affected":[{"ranges":[{"type":"GIT","repo":"https://github.com/madler/zlib"}]}]}],"next_page_token":"tok-1"}`,
		"tok-1": `{"vulns":[{"id":"CVE-2022-37434","database_specific":{"severity":{"nested":true}}},{"id":""}]}`,
	}}
	c := New(Options{Transport: tr})
	vulns, err := c.QueryCommit(context.Background(), zlibCommit)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 2 || vulns[0].ID != "CVE-2018-25032" || vulns[0].Severity != "HIGH" || len(vulns[0].Aliases) != 1 ||
		vulns[1].ID != "CVE-2022-37434" || vulns[1].Severity != "" {
		t.Fatalf("vulns %+v", vulns)
	}
	if len(tr.bodies) != 2 {
		t.Fatalf("%d requests, want 2 (two pages)", len(tr.bodies))
	}
	for i, b := range tr.bodies {
		if tr.urls[i] != "POST https://api.osv.dev/v1/query" || tr.agents[i] != UserAgent {
			t.Errorf("request %d: %s (User-Agent %q)", i, tr.urls[i], tr.agents[i])
		}
		var fields map[string]any
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatalf("body %d is not JSON: %s", i, b)
		}
		if fields["commit"] != zlibCommit {
			t.Errorf("body %d commit %v", i, fields["commit"])
		}
		allowed := map[string]bool{"commit": true}
		if i > 0 {
			allowed["page_token"] = true
		}
		for k := range fields {
			if !allowed[k] {
				t.Errorf("body %d carries %q: only the commit (and a page token) may be sent: %s", i, k, b)
			}
		}
	}
	if !bytes.Equal(tr.bodies[0], []byte(`{"commit":"`+zlibCommit+`"}`)) {
		t.Errorf("first body %s", tr.bodies[0])
	}
}

func TestQueryCommitRefusals(t *testing.T) {
	tr := &capturingTransport{pages: map[string]string{"": `{}`}}
	c := New(Options{Transport: tr})
	for _, bad := range []string{"", zlibCommit[:7], strings.ToUpper(zlibCommit), strings.Repeat("0", 40), strings.Repeat("a", 64), "https://github.com/x/y"} {
		if _, err := c.QueryCommit(context.Background(), bad); err == nil {
			t.Errorf("%q was sent", bad)
		}
	}
	if len(tr.bodies) != 0 {
		t.Fatalf("a refused id reached the transport: %q", tr.bodies)
	}
	// An unknown commit answers {}: no record, no error.
	if v, err := c.QueryCommit(context.Background(), strings.Repeat("1", 40)); err != nil || len(v) != 0 {
		t.Fatalf("unknown commit: %v %v", v, err)
	}
	for name, tr := range map[string]*capturingTransport{
		"a 429":            {pages: map[string]string{"": `{}`}, status: http.StatusTooManyRequests},
		"not JSON":         {pages: map[string]string{"": `<html>`}},
		"a bad page token": {pages: map[string]string{"": `{"next_page_token":"has space"}`}},
		"endless pages":    {pages: map[string]string{"": `{"next_page_token":"a"}`, "a": `{"next_page_token":"a"}`}},
	} {
		if _, err := New(Options{Transport: tr}).QueryCommit(context.Background(), zlibCommit); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestCommitQueryBody(t *testing.T) {
	b, err := CommitQueryBody(zlibCommit, "")
	if err != nil || string(b) != `{"commit":"`+zlibCommit+`"}` {
		t.Fatalf("%s %v", b, err)
	}
	b, err = CommitQueryBody(zlibCommit, "next")
	if err != nil || string(b) != `{"commit":"`+zlibCommit+`","page_token":"next"}` {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := CommitQueryBody(zlibCommit, "bad token"); err == nil {
		t.Fatal("a page token with a space was accepted")
	}
}
