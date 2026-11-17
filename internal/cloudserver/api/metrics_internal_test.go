package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
)

// indirectAuditSites lists the audit() call sites whose event is a variable
// or a constant from another package, keyed by the enclosing function, with
// every value it can take: a name (listed in cloudmetrics) or a family
// prefix ending in "_" (a cloudmetrics family). A new indirect call site
// fails TestAuditEventsAreListed until it is added here.
var indirectAuditSites = map[string][]string{
	"handleSubmitJob":           {"plan_route_unavailable"},
	"writePortalSession":        {"paddle_portal_session_created", "paddle_org_portal_session_created"},
	"handleWorkOSStart":         {"portal_workos_start_"},
	"handlePortalAssertFinish":  {"portal_passkey_assert_failed", "portal_passkey_counter_regressed"},
	"handlePortalPasskeyRemove": {"portal_passkey_removed", "portal_passkey_removed_last"},
	"resolveConnect":            {"connect_approved", "connect_not_now", "connect_declined"},
}

// TestAuditEventsAreListed walks every audit() call in the package and
// checks its event against the closed vocabulary: a literal must be a listed
// name, a "prefix"+suffix concatenation must use a listed family prefix, and
// an indirect value must be in indirectAuditSites. So
// sbci_audit_events_total{event="unlisted"} stays zero.
func TestAuditEventsAreListed(t *testing.T) {
	fams := cloudmetrics.AuditFamilyPrefixes()
	checkValue := func(where, v string) {
		if strings.HasSuffix(v, "_") {
			if !slices.Contains(fams, v) {
				t.Errorf("%s: event family %q is not a cloudmetrics audit family", where, v)
			}
			return
		}
		if got := cloudmetrics.AuditEventLabel(v); got != v {
			t.Errorf("%s: audit event %q is not listed in cloudmetrics (label %q)", where, v, got)
		}
	}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seenIndirect := map[string]bool{}
	calls := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := c.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "audit" || len(c.Args) != 3 {
					return true
				}
				calls++
				where := fset.Position(c.Pos()).String()
				switch a := c.Args[2].(type) {
				case *ast.BasicLit:
					v, err := strconv.Unquote(a.Value)
					if err != nil {
						t.Fatalf("%s: %v", where, err)
					}
					checkValue(where, v)
				case *ast.BinaryExpr:
					left := ast.Expr(a)
					for {
						b, ok := left.(*ast.BinaryExpr)
						if !ok {
							break
						}
						left = b.X
					}
					lit, ok := left.(*ast.BasicLit)
					if !ok {
						t.Errorf("%s: an audit event concatenation must start with a literal family prefix", where)
						return true
					}
					v, _ := strconv.Unquote(lit.Value)
					checkValue(where, v)
				default:
					vals, ok := indirectAuditSites[fd.Name.Name]
					if !ok {
						t.Errorf("%s (%s): indirect audit event; add the function and its values to indirectAuditSites", where, fd.Name.Name)
						return true
					}
					seenIndirect[fd.Name.Name] = true
					for _, v := range vals {
						checkValue(where, v)
					}
				}
				return true
			})
		}
	}
	if calls < 100 {
		t.Fatalf("found only %d audit() calls; the walk is broken", calls)
	}
	for fn := range indirectAuditSites {
		if !seenIndirect[fn] {
			t.Errorf("indirectAuditSites names %s, which no longer has an indirect audit() call", fn)
		}
	}
}

// readStoreSources returns the non-test store sources whose name matches glob.
func readStoreSources(t *testing.T, glob string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "store", glob))
	if err != nil || len(files) == 0 {
		t.Fatalf("no store sources for %s: %v", glob, err)
	}
	var b strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
	}
	return b.String()
}

// TestBindingRefusalReasonsAreListed keeps cloudmetrics' binding reason
// table in step with the store's bindRefusal* constants.
func TestBindingRefusalReasonsAreListed(t *testing.T) {
	src := readStoreSources(t, "paddle*.go")
	re := regexp.MustCompile(`bindRefusal[A-Za-z]+\s*=\s*"([a-z_]+)"`)
	ms := re.FindAllStringSubmatch(src, -1)
	if len(ms) < 5 {
		t.Fatalf("found %d bindRefusal constants; the scan is broken", len(ms))
	}
	listed := cloudmetrics.BindingRefusalReasons()
	for _, m := range ms {
		if !slices.Contains(listed, m[1]) {
			t.Errorf("binding refusal reason %q is not listed in cloudmetrics", m[1])
		}
	}
}

// TestWebhookOutcomesAreListed keeps cloudmetrics' accepted-reason table in
// step with every BillingIntake outcome the store answers and the handler's
// own fallbacks.
func TestWebhookOutcomesAreListed(t *testing.T) {
	src := readStoreSources(t, "*.go")
	re := regexp.MustCompile(`Outcome:\s*"([a-z_]+)"`)
	ms := re.FindAllStringSubmatch(src, -1)
	if len(ms) < 10 {
		t.Fatalf("found %d outcomes; the scan is broken", len(ms))
	}
	listed := cloudmetrics.WebhookReasons(cloudmetrics.WebhookAccepted)
	for _, m := range append(ms, []string{"", "duplicate"}, []string{"", "applied"}, []string{"", "acknowledged"}) {
		if !slices.Contains(listed, m[1]) {
			t.Errorf("webhook outcome %q is not listed in cloudmetrics", m[1])
		}
	}
}

func TestWebhookOutcome(t *testing.T) {
	for _, tc := range []struct {
		status           int
		body             string
		wantRes, wantWhy string
	}{
		{200, `{"status":"processed","outcome":"applied"}`, "accepted", "applied"},
		{200, `{"status":"duplicate","outcome":"duplicate"}`, "accepted", "duplicate"},
		{200, `not json`, "accepted", ""},
		{401, `{"code":"signature_invalid"}`, "refused", "signature_invalid"},
		{501, `{"code":"webhook_not_configured"}`, "refused", "not_configured"},
		{413, `{"code":"body_too_large"}`, "refused", "body_too_large"},
		{400, `{"code":"bad_request"}`, "refused", "bad_envelope"},
		{429, `{"code":"rate_limited"}`, "refused", "rate_limited"},
		{503, `{"code":"rate_limit_unavailable"}`, "refused", "rate_limited"},
		{500, `{"code":"event_processing_failed"}`, "failed", "processing_failed"},
		{500, `{"code":"internal"}`, "failed", "other"},
		{502, ``, "failed", "other"},
		{403, `{"code":"edge_untrusted"}`, "refused", "other"},
	} {
		res, why := webhookOutcome(tc.status, []byte(tc.body))
		if res != tc.wantRes || why != tc.wantWhy {
			t.Errorf("webhookOutcome(%d,%s) = %q,%q; want %q,%q", tc.status, tc.body, res, why, tc.wantRes, tc.wantWhy)
		}
	}
}

func TestAuditLimiter(t *testing.T) {
	var l auditLimiter
	t0 := time.Unix(1_800_000_000, 0)
	win := 10 * time.Minute
	const ev = "paddle_webhook_signature_invalid"

	if w, c := l.admit(ev, "198.51.100.7", win, t0); !w || c != 0 {
		t.Fatalf("first event: write=%v carried=%d", w, c)
	}
	// The probe every 2 minutes inside the window: suppressed.
	for i := 1; i <= 4; i++ {
		if w, _ := l.admit(ev, "198.51.100.7", win, t0.Add(time.Duration(i)*2*time.Minute)); w {
			t.Fatalf("event %d inside the window was written", i)
		}
	}
	// Another source is never suppressed by the first one.
	if w, _ := l.admit(ev, "203.0.113.9", win, t0.Add(3*time.Minute)); !w {
		t.Fatal("a second source's first event must be written")
	}
	// The next window's first row carries the four suppressed ones.
	if w, c := l.admit(ev, "198.51.100.7", win, t0.Add(win)); !w || c != 4 {
		t.Fatalf("next window: write=%v carried=%d, want true 4", w, c)
	}
	// A clock that steps back opens a new window rather than suppressing.
	if w, _ := l.admit(ev, "198.51.100.7", win, t0.Add(-time.Hour)); !w {
		t.Fatal("a backwards clock must not suppress")
	}
	if got := auditRowDetail(4, win); got != `{"suppressed_rows":4,"window_seconds":600}` {
		t.Fatalf("detail %s", got)
	}
	if auditRowDetail(0, win) != "" {
		t.Fatal("no suppressed rows, no detail")
	}
}

func TestAuditLimiterBounded(t *testing.T) {
	var l auditLimiter
	t0 := time.Unix(1_800_000_000, 0)
	win := 10 * time.Minute
	const ev = "paddle_webhook_signature_invalid"
	for i := range auditLimiterMaxSources {
		if w, _ := l.admit(ev, "src-"+strconv.Itoa(i), win, t0); !w {
			t.Fatalf("source %d: first event suppressed", i)
		}
	}
	// Full of live windows: a new source shares the overflow window (its
	// first event is written, the next one inside the window is not).
	if w, _ := l.admit(ev, "new-1", win, t0.Add(time.Second)); !w {
		t.Fatal("overflow window's first event must be written")
	}
	if w, _ := l.admit(ev, "new-2", win, t0.Add(2*time.Second)); w {
		t.Fatal("a second new source inside the overflow window must be suppressed")
	}
	if n := len(l.windows); n > auditLimiterMaxSources+1 {
		t.Fatalf("limiter grew to %d windows", n)
	}
	// Once the windows expire they are dropped and a new source gets its own.
	if w, _ := l.admit(ev, "new-3", win, t0.Add(win+time.Second)); !w {
		t.Fatal("after expiry a new source must be written")
	}
	if n := len(l.windows); n > 2 {
		t.Fatalf("expired windows not dropped: %d", n)
	}
}

// TestPaddleWebhookRouteIsObserved pins the wrapper on the route: the mux
// line must keep observePaddleWebhook outermost.
func TestPaddleWebhookRouteIsObserved(t *testing.T) {
	raw, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	want := `mux.Handle("POST /portal/webhooks/paddle", s.observePaddleWebhook(s.rateLimitWebhook(`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("server.go no longer mounts the Paddle webhook inside observePaddleWebhook (%s)", want)
	}
	if _, ok := auditRowLimits["paddle_webhook_signature_invalid"]; !ok {
		t.Fatal("the invalid-signature row limit is gone")
	}
}
