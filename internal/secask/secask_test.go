package secask

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

func serve(t *testing.T, answer Answerer) string {
	t.Helper()
	if !localipc.Supported() {
		t.Skip("no local IPC transport on this platform")
	}
	dir, err := os.MkdirTemp("", "sa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, ep, err := Listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(ctx, ln, answer) }()
	return ep
}

func echo(status secfeed.OnlineStatus) Answerer {
	return func(_ context.Context, _ secfeed.Scope, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
		var out []secfeed.OnlineAnswer
		for _, s := range specs {
			out = append(out, secfeed.OnlineAnswer{Eco: s.Eco, Name: s.Name, Version: s.Version, Status: status})
		}
		return out
	}
}

func TestAskAnswers(t *testing.T) {
	ep := serve(t, echo(secfeed.OnlineAnswered))
	specs := []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad@1.3.0"), secfeed.ParseSpec(secfeed.EcoPyPI, "Requests")}
	got, err := Ask(context.Background(), ep, secfeed.Scope{ProjectRoot: "/r"}, specs, 1500*time.Millisecond)
	if err != nil || len(got) != 2 || got[0].Version != "1.3.0" {
		t.Fatalf("answers %+v %v", got, err)
	}
}

// TestAskCarriesPrivate: the wire carries a command-private mark (X4) to
// the daemon's answerer.
func TestAskCarriesPrivate(t *testing.T) {
	var seen []secfeed.InstallSpec
	ep := serve(t, func(_ context.Context, _ secfeed.Scope, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
		seen = specs
		return echo(secfeed.OnlineNotAsked)(context.Background(), secfeed.Scope{}, specs)
	})
	sp := secfeed.ParseSpec(secfeed.EcoPyPI, "internal-pkg")
	sp.Private = true
	if _, err := Ask(context.Background(), ep, secfeed.Scope{ProjectRoot: "/r"}, []secfeed.InstallSpec{sp}, time.Second); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || !seen[0].Private {
		t.Errorf("seen %+v", seen)
	}
}

func TestAskBudgetAndFailures(t *testing.T) {
	spec := []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "x-pkg")}
	slow := serve(t, func(ctx context.Context, _ secfeed.Scope, s []secfeed.InstallSpec) []secfeed.OnlineAnswer {
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
		return echo(secfeed.OnlineAnswered)(ctx, secfeed.Scope{}, s)
	})
	start := time.Now()
	got, err := Ask(context.Background(), slow, secfeed.Scope{ProjectRoot: "/r"}, spec, 500*time.Millisecond)
	if el := time.Since(start); el > 700*time.Millisecond {
		t.Errorf("waited %s past a 500 ms budget", el)
	}
	if err == nil && len(got) != 0 {
		t.Errorf("a slow daemon must not answer: %+v", got)
	}

	wrong := serve(t, func(context.Context, secfeed.Scope, []secfeed.InstallSpec) []secfeed.OnlineAnswer {
		return []secfeed.OnlineAnswer{{Eco: secfeed.EcoNpm, Name: "other", Status: secfeed.OnlineAnswered}}
	})
	if _, err := Ask(context.Background(), wrong, secfeed.Scope{ProjectRoot: "/r"}, spec, time.Second); !errors.Is(err, ErrBadAnswer) {
		t.Errorf("an answer about another package: %v", err)
	}

	dir, _ := os.MkdirTemp("", "sd")
	defer func() { _ = os.RemoveAll(dir) }()
	down, _ := Endpoint(dir)
	start = time.Now()
	if _, err := Ask(context.Background(), down, secfeed.Scope{ProjectRoot: "/r"}, spec, time.Second); err == nil {
		t.Error("no daemon must be an error")
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Error("daemon down should fail fast")
	}

	panicky := serve(t, func(context.Context, secfeed.Scope, []secfeed.InstallSpec) []secfeed.OnlineAnswer { panic("boom") })
	if got, err := Ask(context.Background(), panicky, secfeed.Scope{ProjectRoot: "/r"}, spec, time.Second); err != nil || len(got) != 0 {
		t.Errorf("a panicking answerer answers nothing: %+v %v", got, err)
	}
}

func TestHandleRefusesBadRequests(t *testing.T) {
	for _, raw := range []string{`{`, `{"v":2,"specs":[]}`, `{"v":1,"specs":[]} {}`, `{"v":1,"specs":[` + strings.Repeat(`{"eco":"npm","name":"a"},`, MaxSpecs) + `{"eco":"npm","name":"a"}]}`} {
		if r := handle(context.Background(), []byte(raw), echo(secfeed.OnlineAnswered)); r.Reason != "bad_request" {
			t.Errorf("%.40s: %+v", raw, r)
		}
	}
}

// TestHandleIgnoresNewerFields pins lane SEC-DEPS3 item 11: a field a newer
// hook adds to a version 1 request (in the request or in a spec) is ignored
// by this daemon, which answers the rest; it never refuses the ask.
func TestHandleIgnoresNewerFields(t *testing.T) {
	raw := `{"v":1,"project_root":"/r","future_scope":{"x":1},"specs":[{"eco":"npm","name":"left-pad","spec":"left-pad","future":true}],"budget_ms":500}`
	r := handle(context.Background(), []byte(raw), echo(secfeed.OnlineAnswered))
	if r.Reason != "" || len(r.Answers) != 1 || r.Answers[0].Name != "left-pad" {
		t.Fatalf("a newer field must be ignored, the ask answered: %+v", r)
	}
}

// TestAskNotUnderstood pins lane SEC-DEPS3 item 11 on the hook's side: a
// daemon that answers bad_request (an older one, left running across an
// upgrade) is ErrNotUnderstood, not a failed ask, so the hook can keep its
// own offline answer.
func TestAskNotUnderstood(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport on this platform")
	}
	dir, err := os.MkdirTemp("", "sn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, ep, err := Listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, err := readLine(conn); err == nil {
			_, _ = conn.Write([]byte(`{"v":1,"answers":null,"reason":"bad_request"}` + "\n"))
		}
	}()
	spec := []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")}
	if _, err := Ask(context.Background(), ep, secfeed.Scope{ProjectRoot: "/r"}, spec, time.Second); !errors.Is(err, ErrNotUnderstood) {
		t.Fatalf("an older daemon's bad_request must be ErrNotUnderstood: %v", err)
	}
}

func TestEndpointDistinctFromQuickScan(t *testing.T) {
	a, _ := Endpoint("/tmp/x/security")
	if strings.HasSuffix(a, "/tmp/x/security/attach/attach.sock") {
		t.Errorf("the ask endpoint must not be the quick-scan endpoint: %s", a)
	}
}
