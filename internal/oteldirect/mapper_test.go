package oteldirect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/oteldirect/ccfixture"
	"github.com/marmutapp/superbased-observer/internal/otelident"
)

var fixtureStart = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

// whole wraps every record of s into one export.
func whole(s ccfixture.Session) *collogspb.ExportLogsServiceRequest {
	recs := ccfixture.LogRecords(s)
	b := ccfixture.LogBatches(recs[:1])[0]
	b.ResourceLogs[0].ScopeLogs[0].LogRecords = recs
	return b
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestMapLogsDefaultSessionCounts(t *testing.T) {
	cases := []struct {
		name     string
		mod      func(*ccfixture.Session)
		contents int
	}{
		{"no content flags", func(*ccfixture.Session) {}, 0},
		{"prompts", func(s *ccfixture.Session) { s.Prompt = true }, 12},
		{"prompts, tool details, repository", func(s *ccfixture.Session) { s.Prompt, s.ToolDetail, s.Repo = true, true, true }, 12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := ccfixture.Default(fixtureStart)
			c.mod(&s)
			m := MapLogs(whole(s), Options{})
			env := m.Envelope
			if m.Records != 290 || m.Accepted != 290 || m.Rejected != 0 || m.Ignored != 108 || len(m.Reasons) != 0 {
				t.Fatalf("records=%d accepted=%d ignored=%d rejected=%d reasons=%v", m.Records, m.Accepted, m.Ignored, m.Rejected, m.Reasons)
			}
			if len(env.Sessions) != 1 || len(env.APITurns) != 60 || len(env.OTelContent) != c.contents {
				t.Fatalf("sessions=%d turns=%d contents=%d", len(env.Sessions), len(env.APITurns), len(env.OTelContent))
			}
			byType := map[string]int{}
			for _, a := range env.Actions {
				byType[a.ActionType]++
			}
			if len(env.Actions) != 122 || byType[models.ActionUserPrompt] != 12 || byType[models.ActionAPIError] != 2 {
				t.Fatalf("actions=%d by type %v", len(env.Actions), byType)
			}
			if got := len(m.Tools); got != 1 || m.Tools[0] != "claude-code" {
				t.Fatalf("tools = %v", m.Tools)
			}
			if env.AgentVersion != AgentVersion {
				t.Fatalf("agent_version = %q", env.AgentVersion)
			}
			if env.MachineIdentity != "" || env.SourceNodeKey != "" {
				t.Fatalf("identity scalars set: %q %q", env.MachineIdentity, env.SourceNodeKey)
			}
			for _, oc := range env.OTelContent {
				if oc.Kind != "prompt" || oc.Content != ccfixture.PromptText || oc.ContentHash != sha(ccfixture.PromptText) || oc.SessionID != s.ID {
					t.Fatalf("content row = %+v", oc)
				}
			}
		})
	}
}

func TestMapLogsExactRows(t *testing.T) {
	s := ccfixture.Default(fixtureStart)
	s.ToolDetail, s.Repo = true, true
	recs := ccfixture.LogRecords(s)
	m := MapLogs(whole(s), Options{})
	env := m.Envelope

	// The first model call.
	t0 := env.APITurns[0]
	wantCost := ccfixture.CallCost(6, 380, 43800)
	if t0.SessionID != s.ID || t0.RequestID != ccfixture.RequestID(1) || t0.Model != ccfixture.MainModel ||
		t0.Provider != "anthropic" || t0.Timestamp != "2026-11-16T09:00:15Z" ||
		t0.InputTokens != 6 || t0.OutputTokens != 380 || t0.CacheReadTokens != 43800 || t0.CacheCreationTokens != 1400 ||
		t0.CacheCreation1hTokens != 0 || math.Abs(t0.CostUSD-wantCost) > 1e-12 || t0.TotalResponseMS != 4200 ||
		t0.HTTPStatus != 200 || t0.ProjectRoot != ccfixture.HostPath || t0.ProjectRootHash != sha(ccfixture.HostPath) {
		t.Fatalf("turn 0 = %+v", t0)
	}
	// The fifth call of a prompt goes to the small model.
	if got := env.APITurns[4]; got.Model != ccfixture.SmallModel || got.InputTokens != 1200 || got.CacheReadTokens != 0 {
		t.Fatalf("turn 4 = %+v", got)
	}

	src := SourceFileFor("claude-code")
	if src != "otel:claude-code" {
		t.Fatalf("SourceFileFor = %q", src)
	}
	p := env.Actions[0]
	if p.ActionType != models.ActionUserPrompt || p.SourceEventID != "prompt:"+ccfixture.PromptID(0) ||
		p.Timestamp != "2026-11-16T09:00:00Z" || !p.Success || p.Tool != "claude-code" ||
		p.SourceFile != src || p.SourceFileHash != sha(src) || p.Target != "" {
		t.Fatalf("prompt action = %+v", p)
	}
	r := env.Actions[1]
	if r.ActionType != models.ActionReadFile || r.SourceEventID != ccfixture.ToolUseID(1, 0) ||
		r.MessageID != ccfixture.RequestID(1) || r.DurationMs != 30 || !r.Success ||
		r.Timestamp != "2026-11-16T09:00:22.53Z" || r.Target != "internal/retry/handler.go" ||
		r.TargetHash != sha("internal/retry/handler.go") {
		t.Fatalf("read action = %+v", r)
	}
	var bash, apierr int
	for _, a := range env.Actions {
		switch a.ActionType {
		case models.ActionRunCommand:
			bash++
			if a.Target != ccfixture.BashCommand {
				t.Fatalf("bash target = %q", a.Target)
			}
		case models.ActionAPIError:
			if apierr == 0 && (a.SourceEventID != "apierr:"+ccfixture.ErrorRequestID(0) || a.Success || a.DurationMs != 900 || a.ErrorMessage != "Overloaded") {
				t.Fatalf("api_error action = %+v", a)
			}
			apierr++
		}
	}
	if bash == 0 || apierr != 2 {
		t.Fatalf("bash=%d apierr=%d", bash, apierr)
	}

	// Every tool_result's action type is the node adapter's mapping.
	i := 0
	for _, rec := range recs {
		if rec.GetEventName() != "claude_code.tool_result" {
			continue
		}
		name := indexAttrs(rec.GetAttributes()).str([]string{"tool_name"})
		for env.Actions[i].SourceEventID != indexAttrs(rec.GetAttributes()).str([]string{"tool_use_id"}) {
			i++
		}
		if got, want := env.Actions[i].ActionType, ActionTypeFor("claude-code", name); got != want {
			t.Fatalf("%s mapped %q, want %q", name, got, want)
		}
	}

	sess := env.Sessions[0]
	last := time.Unix(0, int64(recs[len(recs)-1].GetTimeUnixNano())).UTC()
	if sess.ID != s.ID || sess.Tool != "claude-code" || sess.Model != ccfixture.MainModel ||
		sess.StartedAt != "2026-11-16T09:00:00Z" || sess.EndedAt != last.Format(time.RFC3339Nano) ||
		sess.TotalActions != 122 || sess.ToolVersion != ccfixture.AppVersion || sess.ToolVersionLast != ccfixture.AppVersion ||
		sess.Surface != models.SurfaceCLI || sess.SurfaceHost != "claude" ||
		sess.ProjectRoot != ccfixture.HostPath || sess.ProjectRootHash != sha(ccfixture.HostPath) ||
		sess.GitRemote != ccfixture.RepositoryURL || sess.GitRemoteHash != sha(ccfixture.RepositoryURL) ||
		sess.GitBranch != ccfixture.Branch || sess.ExecutionLocation != "" || sess.VendorSessionRef != "" || sess.NodeRev != 0 {
		t.Fatalf("session = %+v", sess)
	}
}

// TestMapLogsStreaming maps each 5 s export on its own, the way the route
// sees them, and checks every batch's session row describes that batch.
func TestMapLogsStreaming(t *testing.T) {
	s := ccfixture.Default(fixtureStart)
	batches := ccfixture.LogBatches(ccfixture.LogRecords(s))
	if len(batches) != 182 {
		t.Fatalf("batches = %d, want 182 (the design's measured count)", len(batches))
	}
	var turns, actions, records int
	for bi, b := range batches {
		m := MapLogs(b, Options{})
		var first, last time.Time
		acts := 0
		for _, rec := range b.ResourceLogs[0].ScopeLogs[0].LogRecords {
			at := time.Unix(0, int64(rec.GetTimeUnixNano())).UTC()
			if first.IsZero() || at.Before(first) {
				first = at
			}
			if at.After(last) {
				last = at
			}
			switch rec.GetEventName() {
			case "claude_code.tool_result", "claude_code.user_prompt", "claude_code.api_error":
				acts++
			}
		}
		if len(m.Envelope.Sessions) != 1 {
			t.Fatalf("batch %d: sessions = %d", bi, len(m.Envelope.Sessions))
		}
		sr := m.Envelope.Sessions[0]
		if sr.StartedAt != first.Format(time.RFC3339Nano) || sr.EndedAt != last.Format(time.RFC3339Nano) || sr.TotalActions != acts {
			t.Fatalf("batch %d: session %s..%s actions %d, want %s..%s actions %d", bi, sr.StartedAt, sr.EndedAt, sr.TotalActions,
				first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano), acts)
		}
		wantModel := majority(func() map[string]int {
			c := map[string]int{}
			for _, tr := range m.Envelope.APITurns {
				c[tr.Model]++
			}
			return c
		}())
		if sr.Model != wantModel {
			t.Fatalf("batch %d: model %q, want %q", bi, sr.Model, wantModel)
		}
		turns += len(m.Envelope.APITurns)
		actions += len(m.Envelope.Actions)
		records += m.Accepted
	}
	if turns != 60 || actions != 122 || records != 290 {
		t.Fatalf("streamed turns=%d actions=%d accepted=%d", turns, actions, records)
	}
}

// firstOf returns a clone of the fixture's first record of event.
func firstOf(t *testing.T, s ccfixture.Session, event string) *logspb.LogRecord {
	t.Helper()
	for _, r := range ccfixture.LogRecords(s) {
		if r.GetEventName() == "claude_code."+event {
			return proto.Clone(r).(*logspb.LogRecord)
		}
	}
	t.Fatalf("no %s record", event)
	return nil
}

func without(r *logspb.LogRecord, keys ...string) *logspb.LogRecord {
	drop := map[string]bool{}
	for _, k := range keys {
		drop[k] = true
	}
	var kept []*commonpb.KeyValue
	for _, kv := range r.Attributes {
		if !drop[kv.Key] {
			kept = append(kept, kv)
		}
	}
	r.Attributes = kept
	return r
}

func strKV(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func one(res *resourcepb.Resource, recs ...*logspb.LogRecord) *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: res, ScopeLogs: []*logspb.ScopeLogs{{LogRecords: recs}},
	}}}
}

// TestMapLogsRecordOutcomes: one case per acceptance and rejection rule.
func TestMapLogsRecordOutcomes(t *testing.T) {
	s := ccfixture.Default(fixtureStart)
	cc := ccfixture.Resource()
	svc := func(name string) *resourcepb.Resource {
		return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{strKV("service.name", name)}}
	}
	echo := ccfixture.Resource()
	echo.Attributes = append(echo.Attributes, strKV(otelident.EchoAttr, otelident.EchoValue))
	cases := []struct {
		name                    string
		res                     *resourcepb.Resource
		rec                     func() *logspb.LogRecord
		accepted, ignored, rows int
		reason                  string
	}{
		{"api_request lands a turn", cc, func() *logspb.LogRecord { return firstOf(t, s, "api_request") }, 1, 0, 1, ""},
		{"tool_result lands an action", cc, func() *logspb.LogRecord { return firstOf(t, s, "tool_result") }, 1, 0, 1, ""},
		{"user_prompt lands an action", cc, func() *logspb.LogRecord { return firstOf(t, s, "user_prompt") }, 1, 0, 1, ""},
		{"api_error lands an action", cc, func() *logspb.LogRecord { return firstOf(t, s, "api_error") }, 1, 0, 1, ""},
		{"tool_decision is ignored", cc, func() *logspb.LogRecord { return firstOf(t, s, "tool_decision") }, 1, 1, 0, ""},
		{"assistant_response is ignored", cc, func() *logspb.LogRecord {
			r := firstOf(t, s, "tool_decision")
			r.EventName = "claude_code.assistant_response"
			return without(r, "event.name")
		}, 1, 1, 0, ""},
		{"bare event.name is read", cc, func() *logspb.LogRecord {
			r := firstOf(t, s, "user_prompt")
			r.EventName = ""
			return r
		}, 1, 0, 1, ""},
		{"event.timestamp is the last time fallback", cc, func() *logspb.LogRecord {
			r := firstOf(t, s, "user_prompt")
			r.TimeUnixNano, r.ObservedTimeUnixNano = 0, 0
			return r
		}, 1, 0, 1, ""},
		{"unsupported service.name", svc("codex_exec"), func() *logspb.LogRecord { return firstOf(t, s, "user_prompt") }, 0, 0, 0, ReasonUnsupportedTool},
		{"no service.name", &resourcepb.Resource{}, func() *logspb.LogRecord { return firstOf(t, s, "user_prompt") }, 0, 0, 0, ReasonUnsupportedTool},
		{"Observer's own echo", echo, func() *logspb.LogRecord { return firstOf(t, s, "user_prompt") }, 0, 0, 0, ReasonObserverEcho},
		{"unknown event", cc, func() *logspb.LogRecord {
			r := firstOf(t, s, "user_prompt")
			r.EventName = "claude_code.brand_new_event"
			return without(r, "event.name")
		}, 0, 0, 0, ReasonUnmappedEvent},
		{"no event name", cc, func() *logspb.LogRecord {
			r := firstOf(t, s, "user_prompt")
			r.EventName = ""
			return without(r, "event.name")
		}, 0, 0, 0, ReasonUnmappedEvent},
		{"no session id", cc, func() *logspb.LogRecord { return without(firstOf(t, s, "tool_result"), "session.id") }, 0, 0, 0, ReasonNoSession},
		{"no time", cc, func() *logspb.LogRecord {
			r := without(firstOf(t, s, "user_prompt"), "event.timestamp")
			r.TimeUnixNano, r.ObservedTimeUnixNano = 0, 0
			return r
		}, 0, 0, 0, ReasonNoTimestamp},
		{"api_request without request id", cc, func() *logspb.LogRecord {
			return without(firstOf(t, s, "api_request"), "request_id")
		}, 0, 0, 0, ReasonNoRequestID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := MapLogs(one(c.res, c.rec()), Options{})
			rows := len(m.Envelope.Actions) + len(m.Envelope.APITurns) + len(m.Envelope.OTelContent)
			if m.Records != 1 || m.Accepted != c.accepted || m.Ignored != c.ignored || rows != c.rows {
				t.Fatalf("records=%d accepted=%d ignored=%d rows=%d, want accepted=%d ignored=%d rows=%d",
					m.Records, m.Accepted, m.Ignored, rows, c.accepted, c.ignored, c.rows)
			}
			if c.reason == "" {
				if m.Rejected != 0 || len(m.Envelope.Sessions) != 1 {
					t.Fatalf("rejected=%d %v sessions=%d", m.Rejected, m.Reasons, len(m.Envelope.Sessions))
				}
				return
			}
			if m.Rejected != 1 || m.Reasons[c.reason] != 1 || len(m.Envelope.Sessions) != 0 {
				t.Fatalf("rejected=%d reasons=%v sessions=%d, want 1 %s", m.Rejected, m.Reasons, len(m.Envelope.Sessions), c.reason)
			}
		})
	}
}

func TestMapLogsPromptFallbackIDs(t *testing.T) {
	s := ccfixture.Default(fixtureStart)
	p := without(firstOf(t, s, "user_prompt"), "prompt.id")
	e := without(firstOf(t, s, "api_error"), "request_id")
	tr := without(firstOf(t, s, "tool_result"), "tool_use_id")
	a := MapLogs(one(ccfixture.Resource(), p, e, tr), Options{})
	b := MapLogs(one(ccfixture.Resource(), proto.Clone(p).(*logspb.LogRecord), proto.Clone(e).(*logspb.LogRecord), proto.Clone(tr).(*logspb.LogRecord)), Options{})
	for i := range a.Envelope.Actions {
		id := a.Envelope.Actions[i].SourceEventID
		if id == "" || id != b.Envelope.Actions[i].SourceEventID {
			t.Fatalf("action %d id %q vs %q: not deterministic", i, id, b.Envelope.Actions[i].SourceEventID)
		}
	}
	if !strings.HasPrefix(a.Envelope.Actions[0].SourceEventID, "prompt:") || !strings.HasPrefix(a.Envelope.Actions[1].SourceEventID, "apierr:") ||
		!strings.HasPrefix(a.Envelope.Actions[2].SourceEventID, "tool:") {
		t.Fatalf("ids = %v %v %v", a.Envelope.Actions[0].SourceEventID, a.Envelope.Actions[1].SourceEventID, a.Envelope.Actions[2].SourceEventID)
	}
}

// TestMapLogsNeverCarriesIdentity: the export's identity attributes are
// never used and never land in any row.
func TestMapLogsNeverCarriesIdentity(t *testing.T) {
	s := ccfixture.Default(fixtureStart)
	s.Prompt, s.ToolDetail, s.Repo = true, true, true
	m := MapLogs(whole(s), Options{})
	b, err := json.Marshal(m.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{ccfixture.UserEmail, ccfixture.UserID, ccfixture.AccountUUID, ccfixture.AccountID, ccfixture.OrganizationID} {
		if strings.Contains(string(b), v) {
			t.Fatalf("envelope carries identity value %q", v)
		}
	}
	for _, sr := range m.Envelope.Sessions {
		if sr.UserEmail != "" || sr.OrgID != "" {
			t.Fatalf("session identity set: %+v", sr)
		}
	}
}

func TestMapLogsContentScrubAndCap(t *testing.T) {
	s := ccfixture.Default(fixtureStart)
	s.Prompt = true
	secret := "ghp" + "_aaaabbbbccccddddeeeeffffgggghhhhiiii"
	p := firstOf(t, s, "user_prompt")
	for _, kv := range p.Attributes {
		if kv.Key == "prompt" {
			kv.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "export GITHUB_TOKEN=" + secret + " then " + strings.Repeat("x", 100)}}
		}
	}
	m := MapLogs(one(ccfixture.Resource(), p), Options{ContentMaxBytes: 40})
	if len(m.Envelope.OTelContent) != 1 {
		t.Fatalf("contents = %d", len(m.Envelope.OTelContent))
	}
	oc := m.Envelope.OTelContent[0]
	full := MapLogs(one(ccfixture.Resource(), proto.Clone(p).(*logspb.LogRecord)), Options{}).Envelope.OTelContent[0]
	if strings.Contains(full.Content, secret) || strings.Contains(oc.Content, secret) {
		t.Fatalf("secret not scrubbed: %q", full.Content)
	}
	if len(oc.Content) > 40 {
		t.Fatalf("content not capped: %d bytes", len(oc.Content))
	}
	if oc.ContentHash != sha(full.Content) || oc.ContentHash != full.ContentHash {
		t.Fatal("content hash must cover the full scrubbed body, before the cap")
	}
}

func TestMapLogsCloudExecution(t *testing.T) {
	s := ccfixture.Default(fixtureStart)
	cases := []struct {
		name, ref, wantRef string
	}{
		{"valid reference", "cse_01ABCDEFGHJKMNPQRSTVWXYZ0", "cse_01ABCDEFGHJKMNPQRSTVWXYZ0"},
		{"invalid reference keeps the location only", "bad ref with spaces", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := firstOf(t, s, "user_prompt")
			r.Attributes = append(r.Attributes, strKV("ccr.session.id", c.ref))
			sr := MapLogs(one(ccfixture.Resource(), r), Options{}).Envelope.Sessions[0]
			if sr.ExecutionLocation != models.ExecutionVendorCloud || sr.VendorSessionRef != c.wantRef {
				t.Fatalf("execution = %q ref %q", sr.ExecutionLocation, sr.VendorSessionRef)
			}
		})
	}
}

func TestMapLogsSessionModelMajorityTie(t *testing.T) {
	if got := majority(map[string]int{"b": 2, "a": 2, "c": 1}); got != "a" {
		t.Fatalf("tie = %q, want a", got)
	}
	if got := majority(nil); got != "" {
		t.Fatalf("empty = %q", got)
	}
}

func TestActionTypeFor(t *testing.T) {
	cases := []struct{ native, want string }{
		{"Read", models.ActionReadFile},
		{"Write", models.ActionWriteFile},
		{"Edit", models.ActionEditFile},
		{"MultiEdit", models.ActionEditFile},
		{"Bash", models.ActionRunCommand},
		{"Grep", models.ActionSearchText},
		{"Glob", models.ActionSearchFiles},
		{"WebFetch", models.ActionWebFetch},
		{"WebSearch", models.ActionWebSearch},
		{"TodoWrite", models.ActionTodoUpdate},
		{"Agent", models.ActionSpawnSubagent},
		{"Skill", models.ActionSkillInvoke},
		{"mcp__github__create_issue", models.ActionMCPCall},
		{"BrandNewTool", models.ActionUnknown},
		{"", models.ActionUnknown},
	}
	for _, c := range cases {
		if got := ActionTypeFor("claude-code", c.native); got != c.want {
			t.Errorf("ActionTypeFor(%q) = %q, want %q", c.native, got, c.want)
		}
	}
}

func TestRelativeTo(t *testing.T) {
	cases := []struct{ root, p, want string }{
		{"/home/dev/src/app", "/home/dev/src/app/main.go", "main.go"},
		{"/home/dev/src/app/", "/home/dev/src/app/a/b.go", "a/b.go"},
		{"/home/dev/src/app", "/home/dev/src/app", "."},
		{"/home/dev/src/app", "/etc/hosts", "[external]//etc/hosts"},
		{"/home/dev/src/app", "/home/dev/src/application/x.go", "[external]//home/dev/src/application/x.go"},
		{`C:\src\app`, `C:\src\app\cmd\main.go`, "cmd/main.go"},
		{"/home/dev/src/app", "relative/x.go", "relative/x.go"},
		{"", "/abs/x.go", "/abs/x.go"},
		{"/root", "", ""},
	}
	for _, c := range cases {
		if got := relativeTo(c.root, c.p); got != c.want {
			t.Errorf("relativeTo(%q, %q) = %q, want %q", c.root, c.p, got, c.want)
		}
	}
}
