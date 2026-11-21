package superbased

// The other sdk/contract files every SDK runs: the prompt compile and rollout
// cases, the attribute-key list, the trace-cost recording and the prompt fetch
// recordings; plus the credential-file rules (E-04) each SDK pins in its own
// destination tests.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func readContract(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(contractDir(), name))
	if err != nil {
		t.Skipf("sdk/contract is not present: %v", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestPromptCompileCases(t *testing.T) {
	var f struct {
		Cases []struct {
			Name    string          `json:"name"`
			Type    string          `json:"type"`
			Prompt  json.RawMessage `json:"prompt"`
			Values  map[string]any  `json:"values"`
			Want    json.RawMessage `json:"want"`
			Missing []string        `json:"missing"`
		} `json:"cases"`
	}
	readContract(t, "prompt-compile-cases.json", &f)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			p, err := parsePrompt(decodeJSON([]byte(`{"name":"p","version":1,"type":"`+c.Type+`","prompt":`+string(c.Prompt)+`}`)), "local", "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.Compile(context.Background(), c.Values)
			if c.Missing != nil {
				var ce *PromptCompileError
				if !errors.As(err, &ce) || !reflect.DeepEqual(ce.Missing, c.Missing) {
					t.Fatalf("error %v, want missing %v", err, c.Missing)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			gb, _ := json.Marshal(got)
			var g, w any
			_ = json.Unmarshal(gb, &g)
			_ = json.Unmarshal(c.Want, &w)
			if !reflect.DeepEqual(g, w) {
				t.Fatalf("compiled %s, want %s", gb, c.Want)
			}
		})
	}
}

func TestPromptRolloutCases(t *testing.T) {
	var f struct {
		Cases []struct {
			Salt, ID, Key, Hash, Subject string
			Percent, Bucket              int
			Candidate                    bool
		} `json:"cases"`
	}
	readContract(t, "prompt-rollout-cases.json", &f)
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		h := cohortHash(c.ID)
		if h != c.Hash || c.Key+":"+h != c.Subject {
			t.Fatalf("%s: hash %s, want %s", c.ID, h, c.Hash)
		}
		b := rolloutBucket(c.Salt, c.Subject)
		if b != c.Bucket || (b < c.Percent) != c.Candidate {
			t.Fatalf("%s: bucket %d (candidate %v), want %d (%v)", c.ID, b, b < c.Percent, c.Bucket, c.Candidate)
		}
	}
}

type attributeKeysFile struct {
	Vocabulary           []string       `json:"vocabulary"`
	VocabularyPrefixes   []string       `json:"vocabulary_prefixes"`
	SDKOwned             []string       `json:"sdk_owned"`
	PendingVocabulary    []string       `json:"pending_vocabulary"`
	ContentKeys          []string       `json:"content_keys"`
	ContentPrefixes      []string       `json:"content_prefixes"`
	ContentPrefixExempt  []string       `json:"content_prefix_exempt_suffixes"`
	ExtraContentPrefixes []string       `json:"extra_content_prefixes"`
	Limits               map[string]int `json:"limits"`
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestAttributeKeyListsMatchTheContract(t *testing.T) {
	var f attributeKeysFile
	readContract(t, "sdk-attribute-keys.json", &f)
	var ck []string
	for k := range contentKeys {
		ck = append(ck, k)
	}
	checks := []struct {
		name      string
		got, want []string
	}{
		{"content_keys", sortedCopy(ck), sortedCopy(f.ContentKeys)},
		{"content_prefixes", contentPrefixes, f.ContentPrefixes},
		{"content_prefix_exempt_suffixes", contentPrefixExemptSuffixes, f.ContentPrefixExempt},
		{"extra_content_prefixes", extraContentPrefixes, f.ExtraContentPrefixes},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, c.got, c.want)
		}
	}
	limits := map[string]int{"max_value_len": maxValueLen, "max_tags": maxTags, "max_tag_len": maxTagLen, "max_metadata_keys": maxMetadataKeys,
		"max_metadata_key_len": maxMetadataKeyLen, "max_metadata_value_len": maxMetadataValueLen}
	if !reflect.DeepEqual(limits, f.Limits) {
		t.Errorf("limits %v, want %v", limits, f.Limits)
	}
}

// TestEmitsOnlyListedKeys drives every span helper and setter and checks each
// key the SDK writes is in the contract's lists.
func TestEmitsOnlyListedKeys(t *testing.T) {
	var f attributeKeysFile
	readContract(t, "sdk-attribute-keys.json", &f)
	allowed := map[string]bool{}
	for _, l := range [][]string{f.Vocabulary, f.SDKOwned, f.PendingVocabulary} {
		for _, k := range l {
			allowed[k] = true
		}
	}
	setup(t)
	mem := memInit(t, Options{Tenant: "t", User: "u", SessionID: "s", Release: "r1", Environment: "dev", Tags: []string{"a"}, Metadata: map[string]any{"k": 1}})
	ctx := PropagateAttributes(context.Background(), Attributes{User: "u2", Tags: []string{"b"}, Metadata: map[string]any{"m": "v"}, Release: "r", Environment: "e", Tenant: "t2", SessionID: "s2"})
	p := &Prompt{Name: "p", Version: 2, Label: "production", Rollout: &PromptRollout{Cohort: "base"}}
	_ = WithAgentSpan(ctx, "agent", AgentOptions{AgentID: "a1"}, func(ctx context.Context, _ trace.Span) error {
		_ = WithLLMSpan(ctx, "chat", LLMOptions{Model: "m", Provider: "openai", Prompt: p, System: "be brief"}, func(ctx context.Context, sp trace.Span) error {
			SetRequestParams(sp, RequestParams{MaxTokens: Int(5), Temperature: Float(0.1), TopP: Float(1), TopK: Float(3), StopSequences: []string{"x"},
				FrequencyPenalty: Float(0), PresencePenalty: Float(0), Seed: Int(1), Stream: Bool(true), ReasoningLevel: "low"})
			Admit(ctx, "hi", AdmitOptions{Endpoint: deadURL(t), Timeout: 200 * time.Millisecond})
			return SetUsage(sp, Usage{InputTokens: Int(10), OutputTokens: Int(2), TotalTokens: Int(12), CacheReadTokens: Int(1), CacheWriteTokens: Int(1),
				ReasoningTokens: Int(1), ResponseID: "r", RequestID: "q", ResponseModel: "m2", FinishReasons: []string{"stop"}, CostUSD: Float(0.1),
				Prompt: []Message{{"role": "user", "content": "x"}}, Response: "y"})
		})
		_ = WithToolSpan(ctx, "tool", ToolOptions{CallID: "c", Arguments: map[string]any{"a": 1}}, func(_ context.Context, sp trace.Span) error {
			SetToolResult(sp, "ok")
			return nil
		})
		_ = WithRetrieverSpan(ctx, "ret", RetrieverOptions{Query: "q"}, func(_ context.Context, sp trace.Span) error {
			SetOutput(sp, []string{"doc"})
			return nil
		})
		_ = WithEmbeddingSpan(ctx, "emb", EmbeddingOptions{Model: "e", Provider: "openai"}, func(context.Context, trace.Span) error { return nil })
		_, _ = RunExperiment(ctx, ExperimentOptions{Dataset: []any{"x"}, Task: identityTask})
		return nil
	})
	Flush(context.Background())
	for _, s := range mem.GetSpans() {
		for _, kv := range s.Attributes {
			k := string(kv.Key)
			if allowed[k] || strings.HasPrefix(k, keyMetaPrefix) {
				continue
			}
			t.Errorf("span %q writes %s, which sdk-attribute-keys.json does not list", s.Name, k)
		}
	}
}

func TestTraceCostResponse(t *testing.T) {
	var f struct {
		Org, Machine, NotFound struct {
			Status int            `json:"status"`
			Body   map[string]any `json:"body"`
		}
	}
	raw, err := os.ReadFile(filepath.Join(contractDir(), "trace-cost-response.json"))
	if err != nil {
		t.Skip(err)
	}
	var all map[string]json.RawMessage
	_ = json.Unmarshal(raw, &all)
	_ = json.Unmarshal(all["org"], &f.Org)
	_ = json.Unmarshal(all["machine"], &f.Machine)
	_ = json.Unmarshal(all["not_found"], &f.NotFound)
	tid := "4bf92f3577b34da6a3ce929d0e0e4736"
	for _, tc := range []struct {
		name, dest string
		orgStatus  int
		wantFrom   string
	}{
		{"online", DestinationOnline, 200, DestinationOnline},
		{"local", DestinationLocal, 0, DestinationLocal},
		{"both, org first", DestinationBoth, 200, DestinationOnline},
		{"both, org 404 -> machine", DestinationBoth, 404, DestinationLocal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup(t)
			machine, gw := newStub(t), newStub(t)
			machine.routeBody("GET", "/api/obs/trace/"+tid, f.Machine.Body)
			if tc.orgStatus == 404 {
				gw.route("GET", "/v1/sdk/traces/"+tid+"/cost", func(stubReq) (int, any, map[string]string) { return 404, f.NotFound.Body, nil })
			} else {
				gw.routeBody("GET", "/v1/sdk/traces/"+tid+"/cost", f.Org.Body)
			}
			memInit(t, Options{Destination: tc.dest, NodeURL: machine.URL, OrgURL: gw.URL, APIKey: "ik_1.s"})
			got, err := GetTraceCost(context.Background(), tid)
			if err != nil || got == nil {
				t.Fatalf("%+v, %v", got, err)
			}
			if got.Destination != tc.wantFrom || got.TraceID != tid || len(got.Spans) == 0 || got.CostProvenance.Label == "" {
				t.Fatalf("%+v", got)
			}
			if tc.wantFrom == DestinationOnline {
				if r := gw.seen("/v1/sdk/traces/" + tid + "/cost"); r[0].Headers.Get("Authorization") != "Bearer ik_1.s" || r[0].Headers.Get(apiVersionHeader) != "1" {
					t.Fatalf("headers %v", r[0].Headers)
				}
			}
			for _, r := range machine.seen("") {
				if r.Headers.Get("Authorization") != "" {
					t.Fatal("the key went to the machine")
				}
			}
		})
	}
	setup(t)
	if _, err := GetTraceCost(context.Background(), "xyz"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("a malformed id: %v", err)
	}
	if got, err := GetTraceCost(context.Background(), ""); got != nil || err != nil {
		t.Fatal("no trace must be nil, nil")
	}
	for _, s := range []string{CostGatewayExact, CostProxyExact, CostComputed, CostReported, CostUnpriced} {
		if _, ok := CostSourceLabels[s]; !ok {
			t.Fatalf("no label for %q", s)
		}
	}
}

func TestPromptFetchRecordingAndRevalidation(t *testing.T) {
	var fx struct {
		Headers map[string]string `json:"headers"`
		Body    map[string]any    `json:"body"`
	}
	readContract(t, "prompt-fetch-response.json", &fx)
	setup(t)
	st := newStub(t)
	var calls atomic.Int32
	var inm atomic.Value
	inm.Store("")
	st.route("GET", "/api/obs/sdk/prompts/support-reply", func(r stubReq) (int, any, map[string]string) {
		calls.Add(1)
		if v := r.Headers.Get("If-None-Match"); v != "" {
			inm.Store(v)
			return 304, []byte{}, nil
		}
		return 200, fx.Body, map[string]string{"Etag": fx.Headers["Etag"]}
	})
	memInit(t, Options{NodeURL: st.URL})
	ctx, sp := StartSpan(context.Background(), "req", SpanOptions{})
	p, err := GetPrompt(ctx, "support-reply", PromptOptions{CacheTTL: 50 * time.Millisecond})
	sp.End()
	if err != nil || p.Version != 3 || p.Label != "production" || p.CommitMessage != "tone fix" || p.Source != DestinationLocal {
		t.Fatalf("%+v %v", p, err)
	}
	if got, _ := p.Compile(context.Background(), map[string]any{"customer": "Ada", "topic": "returns"}); got != "Hello Ada, thanks for writing about returns." {
		t.Fatalf("compiled %v", got)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := GetPrompt(context.Background(), "support-reply", PromptOptions{CacheTTL: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for inm.Load() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if inm.Load() != fx.Headers["Etag"] {
		t.Fatalf("If-None-Match %q, want the stored ETag %q", inm.Load(), fx.Headers["Etag"])
	}
	if q := st.seen("/api/obs/sdk/prompts/support-reply")[0].Query; q != "label=production" {
		t.Fatalf("query %q", q)
	}
	// Argument rules.
	for _, o := range []PromptOptions{{Label: "production", Version: 2}, {Label: "dev"}, {Version: -1}} {
		if _, err := GetPrompt(context.Background(), "support-reply", o); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%+v: %v", o, err)
		}
	}
	if _, err := GetPrompt(context.Background(), "-bad", PromptOptions{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestPromptNotFoundAndFallback(t *testing.T) {
	setup(t)
	st := newStub(t)
	st.reply(map[string]any{"error": "prompt_not_found", "message": "no"}, 404, nil)
	memInit(t, Options{NodeURL: st.URL})
	if _, err := GetPrompt(context.Background(), "x", PromptOptions{}); !errors.Is(err, ErrPromptNotFound) {
		t.Fatalf("%v", err)
	}
	p, err := GetPrompt(context.Background(), "x", PromptOptions{Fallback: "Hi {{name}}"})
	if err != nil || !p.IsFallback || p.Version != 0 || p.Source != "fallback" || len(p.Attributes()) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	st.reply(map[string]any{"error": "boom"}, 500, nil)
	if _, err := GetPrompt(context.Background(), "y", PromptOptions{}); !errors.Is(err, ErrPromptFetch) {
		t.Fatalf("%v", err)
	}
	setup(t)
	memInit(t, Options{Destination: DestinationOnline})
	if _, err := GetPrompt(context.Background(), "x", PromptOptions{}); !errors.Is(err, ErrPromptFetch) {
		t.Fatalf("a degraded online is a fetch error: %v", err)
	}
}

func TestPromptRolloutRecordingServesEachSide(t *testing.T) {
	var fx struct {
		Legs []struct {
			Name    string            `json:"name"`
			Query   string            `json:"query"`
			Headers map[string]string `json:"headers"`
			Body    map[string]any    `json:"body"`
		} `json:"legs"`
	}
	readContract(t, "prompt-fetch-rollout-response.json", &fx)
	setup(t)
	st := newStub(t)
	st.route("GET", "/api/obs/sdk/prompts/support-reply", func(r stubReq) (int, any, map[string]string) {
		for _, l := range fx.Legs {
			if l.Query == r.Query {
				return 200, l.Body, map[string]string{"Etag": l.Headers["Etag"]}
			}
		}
		for _, l := range fx.Legs {
			if l.Name == "unkeyed" || !strings.Contains(l.Query, "_hash") {
				return 200, l.Body, nil
			}
		}
		return 404, map[string]any{"error": "prompt_not_found"}, nil
	})
	memInit(t, Options{NodeURL: st.URL})
	cand, err := GetPrompt(context.Background(), "support-reply", PromptOptions{User: "Ünïcode user"})
	if err != nil || cand.Cohort() != "candidate" || cand.Version != 4 {
		t.Fatalf("%+v %v", cand, err)
	}
	base, err := GetPrompt(context.Background(), "support-reply", PromptOptions{User: "alice@example.com"})
	if err != nil || base.Cohort() != "base" || base.Version != 3 {
		t.Fatalf("%+v %v", base, err)
	}
	n := len(st.seen(""))
	again, _ := GetPrompt(context.Background(), "support-reply", PromptOptions{User: "Ünïcode user"})
	if again.Cohort() != "candidate" || len(st.seen("")) != n {
		t.Fatal("a cached side was fetched again")
	}
	for _, r := range st.seen("") {
		if strings.Contains(r.Query, "alice") || strings.Contains(r.Query, "%C3%9C") {
			t.Fatalf("a raw id left the SDK: %s", r.Query)
		}
	}
	found := false
	for _, kv := range cand.Attributes() {
		if kv.Key == keyPromptCohort && kv.Value.AsString() == "candidate" {
			found = true
		}
	}
	if !found {
		t.Fatal("no sbo.prompt.cohort stamp")
	}
}

// --- credential file (E-04) --------------------------------------------------------

func writeCred(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCredentialFileRules(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("credential files are not read on Windows")
	}
	good := writeCred(t, "ik_9a.s3cr3t\ngateway_url=https://gw.example.com:4318\n", 0o600)
	key, gw, problem := readCredentialRecord(good)
	if key != "ik_9a.s3cr3t" || gw != "https://gw.example.com:4318" || problem != "" {
		t.Fatalf("(%q, %q, %q)", key, gw, problem)
	}
	link := filepath.Join(t.TempDir(), "link")
	_ = os.Symlink(good, link)
	for name, path := range map[string]string{
		"symlink":     link,
		"group bits":  writeCred(t, "ik_9a.s\n", 0o640),
		"no equals":   writeCred(t, "ik_9a.s\nnoequals\n", 0o600),
		"empty name":  writeCred(t, "ik_9a.s\n=x\n", 0o600),
		"not a key":   writeCred(t, "nodot\n", 0o600),
		"space":       writeCred(t, "ik_9a.s s\n", 0o600),
		"too long":    writeCred(t, "ik_9a.s\nx="+strings.Repeat("a", 5000)+"\n", 0o600),
		"directory":   t.TempDir(),
		"nonexistent": filepath.Join(t.TempDir(), "missing"),
	} {
		if k, _, p := readCredentialRecord(path); k != "" || p == "" {
			t.Errorf("%s: key %q, problem %q", name, k, p)
		}
	}
	// Unknown names are ignored; no gateway line gives no gateway.
	if k, g, p := readCredentialRecord(writeCred(t, "ik_9a.s\nfuture=1", 0o600)); k != "ik_9a.s" || g != "" || p != "" {
		t.Fatalf("(%q, %q, %q)", k, g, p)
	}
	// An unusable gateway keeps the key and drops the address.
	for _, bad := range []string{"http://gw.example.com", "https://u:p@gw.example.com", "https://gw.example.com/path", "https://gw.example.com?q=1", "ftp://gw.example.com"} {
		k, g, p := readCredentialRecord(writeCred(t, "ik_9a.s\ngateway_url="+bad+"\n", 0o600))
		if k != "ik_9a.s" || g != "" || p == "" {
			t.Errorf("%s: (%q, %q, %q)", bad, k, g, p)
		}
	}
	if _, g, p := readCredentialRecord(writeCred(t, "ik_9a.s\ngateway_url=http://127.0.0.1:4318\n", 0o600)); g != "http://127.0.0.1:4318" || p != "" {
		t.Fatalf("loopback http gateway: %q %q", g, p)
	}
}

// TestDiscoveryNeverChoosesWhereTheKeyGoes: a fake discovery answer that names
// an attacker gateway and attacker local URLs sends nothing off loopback; the
// key goes only to the credential file's gateway (review E-04).
func TestDiscoveryNeverChoosesWhereTheKeyGoes(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("credential files are not read on Windows")
	}
	setup(t)
	st := newStub(t)
	cred := writeCred(t, "ik_9a.s3cr3t\ngateway_url=https://gw.example.com\n", 0o600)
	st.routeBody("GET", "/api/sdk/destination", map[string]any{"api_version": 1, "destination": "both", "source": "default_signed_in", "signed_in": true,
		"local":  map[string]any{"enabled": true, "otlp_traces_url": "https://evil.example/v1/traces", "admission_url": "https://evil.example/check"},
		"online": map[string]any{"gateway_url": "https://evil.example", "credential_present": true, "credential_file": cred}, "warnings": []any{}})
	e := mapEnv(map[string]string{"SUPERBASED_DISCOVER": "1", "SUPERBASED_NODE_URL": st.URL})
	s, _ := resolveSettings(e, Options{})
	p := resolvePlan(s, e, explicitInputs{})
	if p.destination != DestinationBoth || p.gatewayURL != "https://gw.example.com" || p.key != "ik_9a.s3cr3t" || p.credentialFrom != "file" {
		t.Fatalf("%+v", p)
	}
	for _, x := range p.exporters {
		if strings.Contains(x.endpoint, "evil") {
			t.Fatalf("exporter %s", x.endpoint)
		}
	}
	if strings.Contains(p.admitURL, "evil") || strings.Contains(p.machineAdmit, "evil") {
		t.Fatalf("admit %s / %s", p.admitURL, p.machineAdmit)
	}
	if len(p.warnings) < 2 {
		t.Fatalf("want warnings for the non-loopback local URLs: %v", p.warnings)
	}
	// A non-loopback node URL is never asked.
	body, err := discover("https://machine.example.com")
	if body != nil || !strings.Contains(err, "not a loopback") {
		t.Fatalf("%v %q", body, err)
	}
}

func TestDegradedOnlineAndBoth(t *testing.T) {
	setup(t)
	memInit(t, Options{Destination: DestinationOnline})
	d := GetDiagnostics()
	if !strings.Contains(d.Degraded, "observer sdk sign-in") || len(d.Destinations) != 0 {
		t.Fatalf("%+v", d)
	}
	_, sp := StartSpan(context.Background(), "x", SpanOptions{})
	sp.End()
	if GetDiagnostics().DroppedSpans != 1 {
		t.Fatal("a span with nowhere to go is counted as dropped")
	}
	r := Score(context.Background(), "x", 1, ScoreOptions{TraceID: strings.Repeat("a", 32)})
	if r.OK || r.Destinations[DestinationOnline].Error == "" {
		t.Fatalf("%+v", r)
	}
	setup(t)
	memInit(t, Options{Destination: DestinationBoth})
	d = GetDiagnostics()
	if !strings.Contains(d.Degraded, "this machine only") || len(d.Destinations) != 1 || d.Destinations[0].Name != DestinationLocal {
		t.Fatalf("%+v", d)
	}
}

func TestInvalidDestinationFallsThrough(t *testing.T) {
	setup(t)
	t.Setenv("SUPERBASED_DESTINATION", "both")
	memInit(t, Options{Destination: "cloud"})
	d := GetDiagnostics()
	if d.Destination != DestinationBoth || d.DestinationSource != "env" || len(d.Warnings) == 0 {
		t.Fatalf("%+v", d)
	}
}

var _ = attribute.String
var _ = tracetest.NewInMemoryExporter
