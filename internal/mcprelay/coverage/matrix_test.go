package coverage

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestMatrix_EveryVerifiedClientHasRows pins doc3 §12.7 completeness: every
// verified client (an MCP registry, a blocking hook or a proxy route in the
// integration registry) has exactly one row per transport x method, and the
// matrix derives from the registry (never a hand list).
func TestMatrix_EveryVerifiedClientHasRows(t *testing.T) {
	t.Parallel()
	clients := VerifiedClients()
	if len(clients) == 0 {
		t.Fatal("no verified clients derived from the integration registry")
	}
	rows := Matrix(Live{})
	per := map[string]int{}
	for _, r := range rows {
		per[r.Client]++
		if r.Coverage == "" {
			t.Errorf("%+v has no coverage label", r)
		}
		if (r.Coverage == Mediated || r.Coverage == HookOnly || r.Coverage == BestEffort) && r.Point == "" {
			t.Errorf("%+v claims coverage without an enforcement point", r)
		}
		if r.Coverage == Planned && r.Phase == "" {
			t.Errorf("%+v is planned without a phase (R8.23.o)", r)
		}
		if r.Coverage == Uncovered && r.Point != "" {
			t.Errorf("%+v is uncovered but names a point", r)
		}
	}
	want := len(Transports) * len(Methods)
	for _, c := range clients {
		if per[c] != want {
			t.Errorf("client %s has %d rows, want %d", c, per[c], want)
		}
	}
	// Registry clients with an MCP registry are all verified.
	for _, c := range integration.Capabilities() {
		if c.MCP != nil && per[c.Tool] == 0 {
			t.Errorf("registry MCP client %s missing from the matrix", c.Tool)
		}
	}
}

// TestCellFor_Rows is the derivation table's one-case-per-row test.
func TestCellFor_Rows(t *testing.T) {
	t.Parallel()
	full := ClientShape{Client: "x", HasMCPRegistry: true, RegistryWriterImplemented: true, SupportsRemote: true, ProjectionApplied: true, StdioApplied: true, RemoteApplied: true, RemoteWired: true, HookBlocks: true, ProxyRoutable: true}
	writerOnly := ClientShape{Client: "w", HasMCPRegistry: true, RegistryWriterImplemented: true, SupportsRemote: true}
	appliedNoToken := ClientShape{Client: "a", HasMCPRegistry: true, RegistryWriterImplemented: true, SupportsRemote: true, ProjectionApplied: true, StdioApplied: true, RemoteApplied: true}
	// Sol P3+P4 fold finding 3: per-transport applied, never cross-fed.
	stdioOnlyToken := ClientShape{Client: "s", HasMCPRegistry: true, RegistryWriterImplemented: true, SupportsRemote: true, ProjectionApplied: true, StdioApplied: true, RemoteWired: true}
	remoteOnly := ClientShape{Client: "r", HasMCPRegistry: true, RegistryWriterImplemented: true, SupportsRemote: true, ProjectionApplied: true, RemoteApplied: true, RemoteWired: true}
	legacyAnyApplied := ClientShape{Client: "l", HasMCPRegistry: true, RegistryWriterImplemented: true, SupportsRemote: true, ProjectionApplied: true, RemoteWired: true}
	partial := full
	partial.StdioUnmediated = 1
	partialNoHook := partial
	partialNoHook.HookBlocks = false
	cases := []struct {
		name  string
		shape ClientShape
		t     Transport
		m     Method
		want  Coverage
		point string
	}{
		{"stdio partially projected (an unbound / new entry runs direct), hook blocks = hook-only", partial, TransportStdio, MethodGoverned, HookOnly, PointHook},
		{"stdio partially projected, no hook = uncovered", partialNoHook, TransportStdio, MethodCatalogue, Uncovered, ""},
		{"stdio-only row + token client: remote NOT mediated", stdioOnlyToken, TransportRemoteHTTP, MethodCatalogue, Uncovered, ""},
		{"stdio-only row + token client: stdio mediated", stdioOnlyToken, TransportStdio, MethodGoverned, Mediated, PointRelay},
		{"remote-only row: stdio NOT mediated", remoteOnly, TransportStdio, MethodCatalogue, Uncovered, ""},
		{"remote-only row + token: remote mediated", remoteOnly, TransportRemoteHTTP, MethodGoverned, Mediated, PointRelay},
		{"legacy any-transport flag alone mediates nothing (stdio)", legacyAnyApplied, TransportStdio, MethodCatalogue, Uncovered, ""},
		{"legacy any-transport flag alone mediates nothing (remote)", legacyAnyApplied, TransportRemoteHTTP, MethodCatalogue, Uncovered, ""},
		{"stdio + writer + applied = mediated (governed)", full, TransportStdio, MethodGoverned, Mediated, PointRelay},
		{"stdio + writer + applied = mediated (catalogue)", full, TransportStdio, MethodCatalogue, Mediated, PointRelay},
		{"stdio + writer NOT applied = uncovered, never mediated", writerOnly, TransportStdio, MethodGoverned, Uncovered, ""},
		{"stdio + writer NOT applied but hook blocks = hook-only", ClientShape{HasMCPRegistry: true, RegistryWriterImplemented: true, HookBlocks: true}, TransportStdio, MethodGoverned, HookOnly, PointHook},
		{"stdio registry without writer = planned", ClientShape{HasMCPRegistry: true}, TransportStdio, MethodGoverned, Planned, ""},
		{"remote + writer + remote-capable + applied + token = mediated", full, TransportRemoteHTTP, MethodGoverned, Mediated, PointRelay},
		{"remote applied but no token client = uncovered", appliedNoToken, TransportRemoteHTTP, MethodGoverned, Uncovered, ""},
		{"remote projectable but not applied = uncovered", writerOnly, TransportRemoteHTTP, MethodCatalogue, Uncovered, ""},
		{"remote, registry not remote-capable, hook blocks = hook-only", ClientShape{HasMCPRegistry: true, RegistryWriterImplemented: true, HookBlocks: true}, TransportRemoteHTTP, MethodGoverned, HookOnly, PointHook},
		{"hosted connector + proxied = best-effort", full, TransportHostedConnector, MethodGoverned, BestEffort, PointProxyTools},
		{"hosted connector, not proxied, hook blocks = hook-only", ClientShape{HookBlocks: true}, TransportHostedConnector, MethodGoverned, HookOnly, PointHook},
		{"catalogue on proxied client without registry = best-effort", ClientShape{ProxyRoutable: true}, TransportRemoteHTTP, MethodCatalogue, BestEffort, PointProxyTools},
		{"no registry, no hook, no proxy = uncovered", ClientShape{}, TransportStdio, MethodGoverned, Uncovered, ""},
		{"hosted connector, no proxy, no hook = uncovered", ClientShape{HasMCPRegistry: true, RegistryWriterImplemented: true}, TransportHostedConnector, MethodCatalogue, Uncovered, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := CellFor(tc.shape, tc.t, tc.m)
			if got.Coverage != tc.want || got.Point != tc.point {
				t.Errorf("cell = %s/%q, want %s/%q (%s)", got.Coverage, got.Point, tc.want, tc.point, got.Note)
			}
		})
	}
}

// TestShapeOf_DispatchesOnCapabilityShape pins CLAUDE.md rule 3: the shape
// comes from the registry row's capabilities, and the two known extremes
// (claude-code: registry + blocking hook + proxy; a registry-less row) map
// as expected without any tool-name branch in this package.
func TestShapeOf_DispatchesOnCapabilityShape(t *testing.T) {
	t.Parallel()
	cc, ok := integration.For("claude-code")
	if !ok {
		t.Fatal("claude-code missing from the registry")
	}
	// Nothing live: the registry row alone never yields a writer, an
	// applied projection or remote forwarding (coverage honesty).
	s := ShapeOf(cc, Live{})
	if !s.HasMCPRegistry || s.RegistryWriterImplemented || s.ProjectionApplied || s.RemoteWired || !s.SupportsRemote || !s.HookBlocks || !s.ProxyRoutable {
		t.Errorf("claude-code shape with nothing live = %+v", s)
	}
	live := Live{
		WrapWriter:    func(f integration.MCPFormat) bool { return f == integration.MCPServersJSON },
		AppliedStdio:  func(tool string) bool { return tool == "claude-code" },
		AppliedRemote: func(tool string) bool { return tool == "claude-code" },
		RemoteWired:   true,
	}
	s = ShapeOf(cc, live)
	if !s.RegistryWriterImplemented || !s.ProjectionApplied || !s.StdioApplied || !s.RemoteApplied || !s.RemoteWired {
		t.Errorf("claude-code shape with live caps = %+v", s)
	}
	// The legacy any-transport flag feeds ProjectionApplied only, never a
	// transport predicate.
	if ls := ShapeOf(cc, Live{Applied: func(string) bool { return true }}); !ls.ProjectionApplied || ls.StdioApplied || ls.RemoteApplied {
		t.Errorf("legacy Applied leaked into a transport predicate: %+v", ls)
	}
	if us := ShapeOf(cc, Live{StdioUnmediated: func(string) int { return 2 }}); us.StdioUnmediated != 2 {
		t.Errorf("StdioUnmediated not carried: %+v", us)
	}
	// hermes: registry row Implemented (the init YAML writer) but no wrap
	// writer and Remote.Implemented=false -> neither writer nor remote.
	if hm, ok := integration.For("hermes"); ok {
		hs := ShapeOf(hm, live)
		if hs.RegistryWriterImplemented || hs.SupportsRemote {
			t.Errorf("hermes shape = %+v (no wrap writer, remote not implemented)", hs)
		}
	}
	if got := ShapeOf(integration.Capability{Tool: "nothing"}, live); got.HasMCPRegistry || got.HookBlocks || got.ProxyRoutable || got.ProjectionApplied {
		t.Errorf("empty capability shape = %+v", got)
	}
	// The matrix flips a client's stdio rows to mediated ONLY once the
	// projection is applied (and a real writer exists).
	before := Matrix(Live{WrapWriter: live.WrapWriter})
	after := Matrix(live)
	find := func(rows []Row, tool string, tr Transport) Row {
		for _, r := range rows {
			if r.Client == tool && r.Transport == tr && r.Method == MethodGoverned {
				return r
			}
		}
		return Row{}
	}
	if b := find(before, "claude-code", TransportStdio); b.Coverage == Mediated {
		t.Errorf("stdio row mediated before any projection: %+v", b)
	}
	if a := find(after, "claude-code", TransportStdio); a.Coverage != Mediated {
		t.Errorf("stdio row not mediated after projection: %+v", a)
	}
	if a := find(after, "claude-code", TransportRemoteHTTP); a.Coverage != Mediated {
		t.Errorf("remote row not mediated with projection + token client: %+v", a)
	}
	if Summary(Matrix(Live{}))[Mediated] != 0 {
		t.Error("a matrix with nothing live claims mediation")
	}
}

// TestEffectiveHash_Golden pins the R8.15 hash: deterministic, capability-
// order independent, and sensitive to every input member.
func TestEffectiveHash_Golden(t *testing.T) {
	t.Parallel()
	base := EffectiveInput{
		PolicyVersion: 7, CompiledSubsetHash: strings.Repeat("a", 64),
		PointCapabilitySet: []string{"table.loaded", "hook.pretooluse_registered", "hook.known_tool_shapes"},
		ClientID:           "claude-code", ClientVersion: "2.1.0", ClientConfigState: "projected",
	}
	got := EffectiveHash(base)
	if len(got) != 64 {
		t.Fatalf("hash = %q, want 64 hex", got)
	}
	reordered := base
	reordered.PointCapabilitySet = []string{"hook.known_tool_shapes", "table.loaded", "hook.pretooluse_registered", "table.loaded"}
	if EffectiveHash(reordered) != got {
		t.Error("hash depends on capability order / duplicates")
	}
	if EffectiveHash(base) != got {
		t.Error("hash not deterministic")
	}
	for name, mut := range map[string]func(*EffectiveInput){
		"policy_version":       func(i *EffectiveInput) { i.PolicyVersion++ },
		"compiled_subset_hash": func(i *EffectiveInput) { i.CompiledSubsetHash = strings.Repeat("b", 64) },
		"capability_set":       func(i *EffectiveInput) { i.PointCapabilitySet = i.PointCapabilitySet[:1] },
		"client_id":            func(i *EffectiveInput) { i.ClientID = "codex" },
		"client_version":       func(i *EffectiveInput) { i.ClientVersion = "2.1.1" },
		"client_config_state":  func(i *EffectiveInput) { i.ClientConfigState = "drifted" },
	} {
		m := base
		m.PointCapabilitySet = append([]string(nil), base.PointCapabilitySet...)
		mut(&m)
		if EffectiveHash(m) == got {
			t.Errorf("hash insensitive to %s", name)
		}
	}
}

// exactGolden is sha256 of the canonical JSON named in TestEffectiveHash_Exact.
const exactGolden = "49d6740c6afa6286bc9a2299f41d90f6e937b3636210697d23ce9cb98eed4136"

// TestEffectiveHash_Exact pins the exact digest of a fixed input so a
// canonicalisation change (member order, whitespace) is loud.
func TestEffectiveHash_Exact(t *testing.T) {
	t.Parallel()
	in := EffectiveInput{PolicyVersion: 1, CompiledSubsetHash: "h", PointCapabilitySet: []string{"b", "a"}, ClientID: "c", ClientVersion: "v", ClientConfigState: "s"}
	// sha256 of {"client_config_state":"s","client_id":"c","client_version":"v","compiled_subset_hash":"h","point_capability_set":["a","b"],"policy_version":1}
	if got := EffectiveHash(in); got != exactGolden {
		t.Errorf("hash = %s, want %s", got, exactGolden)
	}
}

// TestStatus_MissingCapabilityIsIneffective pins doc2-18: a point missing
// ANY required capability reports ineffective, never effective; an unknown
// point is ineffective too.
func TestStatus_MissingCapabilityIsIneffective(t *testing.T) {
	t.Parallel()
	for point, req := range RequiredCapabilities {
		if st, missing := Status(point, req); st != StatusEffective || len(missing) != 0 {
			t.Errorf("%s with all caps = %s missing %v", point, st, missing)
		}
		if st, missing := Status(point, req[1:]); st != StatusIneffective || len(missing) != 1 || missing[0] != req[0] {
			t.Errorf("%s missing %s = %s missing %v", point, req[0], st, missing)
		}
		if st, _ := Status(point, nil); st != StatusIneffective {
			t.Errorf("%s with no caps = %s", point, st)
		}
	}
	if st, _ := Status("not-a-point", []string{"table.loaded"}); st != StatusIneffective {
		t.Errorf("unknown point = %s", st)
	}
}

// TestRender_ListsEveryRowAndSummary pins the CLI body shape.
func TestRender_ListsEveryRowAndSummary(t *testing.T) {
	t.Parallel()
	rows := Matrix(Live{})
	out := Render(rows)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// header + rows + summary + honesty footer
	if len(lines) != len(rows)+3 {
		t.Fatalf("render lines = %d, want %d", len(lines), len(rows)+3)
	}
	if !strings.Contains(out, "summary: mediated=") || !strings.Contains(out, "BEST-EFFORT") {
		t.Errorf("render missing summary/honesty footer:\n%s", out)
	}
}
