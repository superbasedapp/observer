//go:build !sbo_omit_security && !sbo_omit_security_dast

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secdast"
	"github.com/marmutapp/superbased-observer/internal/secdastnet"
)

func TestSecurityDASTIsOptIn(t *testing.T) {
	if !securityOptIn[secdast.ComponentID] {
		t.Fatal("security.dast must be opt-in (plan 14.13): with no [components] block no verb may run")
	}
}

func TestDASTAccept(t *testing.T) {
	home := t.TempDir()
	e := dastEnv{dir: filepath.Join(home, "security")}
	var out bytes.Buffer
	// Not a terminal and no --yes: nothing recorded.
	if err := runDASTAccept(&out, strings.NewReader("y\n"), e, false, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if e.consent().Accepted() || !strings.Contains(out.String(), "Nothing recorded") {
		t.Fatalf("recorded without a yes: %s", out.String())
	}
	// A terminal answer of n records nothing; y does.
	out.Reset()
	if err := runDASTAccept(&out, strings.NewReader("n\n"), e, false, true, time.Now()); err != nil || e.consent().Accepted() {
		t.Fatalf("an n recorded: %v", err)
	}
	if err := runDASTAccept(&out, strings.NewReader("y\n"), e, false, true, time.Now()); err != nil || !e.consent().Accepted() {
		t.Fatalf("a y did not record: %v", err)
	}
	if _, err := os.Stat(e.keyPath()); err != nil {
		t.Fatalf("no posture key beside the security directory: %v", err)
	}
	out.Reset()
	if err := runDASTAccept(&out, strings.NewReader(""), e, true, false, time.Now()); err != nil || !strings.Contains(out.String(), "Already accepted") {
		t.Fatalf("second accept: %v %s", err, out.String())
	}
}

func TestRunDASTAgainstLoopbackServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("X-Powered-By", "Express")
			_, _ = w.Write([]byte("<html><body>ok</body></html>"))
		case "/.env":
			_, _ = w.Write([]byte("TOKEN=secret-value-123\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	tg, err := secdast.ParseTarget(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDAST(context.Background(), &out, tg, secdastnet.Options{}, true, time.Now(), dastRecorder{}); err != nil {
		t.Fatal(err)
	}
	var view dastReportView
	if err := json.Unmarshal(out.Bytes(), &view); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	rules := map[string]bool{}
	for _, f := range view.Findings {
		rules[f.Rule] = true
	}
	if view.Outcome != secdast.OutcomeComplete || !rules["dast.exposed.env"] || !rules["dast.headers.csp-missing"] || !rules["dast.banner.version"] {
		t.Fatalf("report %+v", view)
	}
	if strings.Contains(out.String(), "secret-value-123") {
		t.Fatal("the .env body reached the report")
	}
	out.Reset()
	if err := runDAST(context.Background(), &out, tg, secdastnet.Options{}, false, time.Now(), dastRecorder{}); err != nil || !strings.Contains(out.String(), "flag only") {
		t.Fatalf("text report: %v %s", err, out.String())
	}
}

func TestRunDASTUnreachableIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	tg, err := secdast.ParseTarget(url + "/")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = runDAST(context.Background(), &out, tg, secdastnet.Options{}, false, time.Now(), dastRecorder{})
	if err == nil || !strings.Contains(err.Error(), "nothing was checked") || !strings.Contains(out.String(), secdast.OutcomeUnreachable) {
		t.Fatalf("unreachable run: %v %s", err, out.String())
	}
}

func TestRunDASTCandidates(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := runDASTCandidates(&out, dir, false); err != nil || !strings.Contains(out.String(), "No dev server found") {
		t.Fatalf("no launch.json: %v %s", err, out.String())
	}
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "launch.json"), []byte(`{"configurations":[{"name":"web","port":5173},{"name":"far","url":"https://example.com"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runDASTCandidates(&out, dir, false); err != nil || !strings.Contains(out.String(), "http://localhost:5173/  web (launch.json)") || strings.Contains(out.String(), "example.com") {
		t.Fatalf("candidates: %v %s", err, out.String())
	}
}
