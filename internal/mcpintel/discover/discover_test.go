// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package discover

import (
	"regexp"
	"strings"
	"testing"
)

func TestTransportClassAndRegistryTransport(t *testing.T) {
	for _, tc := range []struct {
		in, class, reg string
	}{
		{"", "", ""},
		{"stdio", ClassStdio, RegistryNodeLocalStdio},
		{"STDIO", ClassStdio, RegistryNodeLocalStdio},
		{"local", ClassStdio, RegistryNodeLocalStdio},
		{"http", ClassRemote, RegistryStreamableHTTP},
		{"streamable-http", ClassRemote, RegistryStreamableHTTP},
		{"streamable_http", ClassRemote, RegistryStreamableHTTP},
		{"sse", ClassRemote, RegistrySSELegacy},
		{"sse_legacy", ClassRemote, RegistrySSELegacy},
	} {
		if got := TransportClass(tc.in); got != tc.class {
			t.Errorf("TransportClass(%q) = %q, want %q", tc.in, got, tc.class)
		}
		if got := RegistryTransport(tc.in); got != tc.reg {
			t.Errorf("RegistryTransport(%q) = %q, want %q", tc.in, got, tc.reg)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"https://MCP.Example.com/", "https://mcp.example.com", true},
		{"https://mcp.example.com:443/v1/", "https://mcp.example.com/v1", true},
		{"http://mcp.example.com:80/x", "http://mcp.example.com/x", true},
		{"https://mcp.example.com:8443/x", "https://mcp.example.com:8443/x", true},
		{"https://user:s3cret@mcp.example.com/x#frag", "https://mcp.example.com/x", true},
		{"https://mcp.example.com/x?b=2&a=1", "https://mcp.example.com/x?a=1&b=2", true},
		{"http://[::1]:80/mcp", "http://[::1]/mcp", true},
		{"http://[::1]:9000/mcp", "http://[::1]:9000/mcp", true},
		{"not a url", "", false},
		{"/relative/path", "", false},
		{"", "", false},
	} {
		got, ok := NormalizeURL(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestLocatorFingerprint pins the identity properties R13.7 relies on:
// non-empty hex, stable over URL spelling noise and userinfo, sensitive to
// the parts of the canonical locator, and never colliding across classes.
func TestLocatorFingerprint(t *testing.T) {
	remote := LocatorFingerprint(Locator{Transport: "http", URL: "https://mcp.example.com/v1"})
	for _, same := range []Locator{
		{Transport: "http", URL: "https://MCP.example.com:443/v1/"},
		{Transport: "streamable-http", URL: "https://u:p@mcp.example.com/v1#x"},
		// Args / command / config path are not part of a REMOTE identity.
		{Transport: "http", URL: "https://mcp.example.com/v1", Command: "x", Args: []string{"y"}, ConfigPathHash: "z"},
	} {
		if got := LocatorFingerprint(same); got != remote {
			t.Errorf("remote fingerprint moved for %+v", same)
		}
	}
	if !hex64.MatchString(remote) {
		t.Fatalf("fingerprint %q is not lower-hex sha256", remote)
	}
	for _, diff := range []Locator{
		{Transport: "http", URL: "https://mcp.example.com/v2"},
		{Transport: "sse", URL: "https://mcp.example.com/v1"},
		{Transport: "http", URL: "https://other.example.com/v1"},
	} {
		if LocatorFingerprint(diff) == remote {
			t.Errorf("distinct remote locator %+v collided", diff)
		}
	}

	stdio := Locator{Transport: "stdio", Command: "npx", Args: []string{"-y", "@acme/mcp"}, ConfigPathHash: ConfigPathHash("/home/dev/.claude.json")}
	base := LocatorFingerprint(stdio)
	if LocatorFingerprint(stdio) != base {
		t.Fatal("stdio fingerprint is not deterministic")
	}
	mut := []func(l Locator) Locator{
		func(l Locator) Locator { l.Command = "node"; return l },
		func(l Locator) Locator { l.Args = []string{"-y", "@acme/mcp", "--x"}; return l },
		func(l Locator) Locator { l.Args = []string{"-y@acme/mcp"}; return l }, // field-split collision guard
		func(l Locator) Locator { l.ConfigPathHash = ConfigPathHash("/home/dev/.cursor/mcp.json"); return l },
	}
	for i, m := range mut {
		if LocatorFingerprint(m(stdio)) == base {
			t.Errorf("stdio mutation %d did not move the fingerprint", i)
		}
	}
	if PinLocatorFingerprint("claude-code", "github") == LocatorFingerprint(Locator{Transport: "stdio", Command: "github"}) {
		t.Fatal("pin and inventory fingerprints share a domain")
	}
	if PinLocatorFingerprint("claude-code", "github") == PinLocatorFingerprint("cursor", "github") {
		t.Fatal("pin fingerprint ignores the client")
	}
}

func TestServerNameHash(t *testing.T) {
	a := ServerNameHash("org-a", "github")
	if !strings.HasPrefix(a, ServerNameHashPrefix) || !hex64.MatchString(strings.TrimPrefix(a, ServerNameHashPrefix)) {
		t.Fatalf("hash %q is not typed hmac-sha256:v1:<hex64>", a)
	}
	if ServerNameHash("org-a", "github") != a {
		t.Fatal("not deterministic")
	}
	if ServerNameHash("org-b", "github") == a {
		t.Fatal("two orgs' hashes of one name correlate (the key must be per org)")
	}
	if ServerNameHash("org-a", "gitlab") == a {
		t.Fatal("distinct names collide")
	}
	if ConfigPathHash("") != "" {
		t.Fatal("empty path must hash to empty")
	}
}

func TestMatchRegistry(t *testing.T) {
	reg := []RegistryServer{
		{ID: "s-url", Name: "io.acme/remote", Transport: RegistryStreamableHTTP, URL: "https://mcp.acme.io/mcp", Status: "approved"},
		{ID: "s-exact", Name: "exactname", Status: "draft"},
		{ID: "s-suffix", Name: "io.github.owner/github", Status: "approved"},
		{ID: "s-retired", Name: "io.acme/gone", URL: "https://gone.acme.io", Status: "retired"},
	}
	for _, tc := range []struct {
		name, nameHash, url string
		rule, id            string
	}{
		{"whatever", "", "https://MCP.acme.io:443/mcp/", MatchURL, "s-url"},
		{"exactname", "", "", MatchExact, "s-exact"},
		{"github", "", "", MatchSuffix, "s-suffix"},
		{"", ServerNameHash("org", "github"), "", MatchNameHash, "s-suffix"},
		{"", ServerNameHash("org", "io.github.owner/github"), "", MatchNameHash, "s-suffix"},
		{"", ServerNameHash("other-org", "github"), "", MatchNone, ""},
		{"gone", "", "https://gone.acme.io", MatchNone, ""}, // retired never matches
		{"unknown", ServerNameHash("org", "unknown"), "https://x.example", MatchNone, ""},
	} {
		m := MatchRegistry("org", tc.name, tc.nameHash, tc.url, reg)
		if m.Rule != tc.rule || m.ServerID != tc.id || m.Registered != (tc.rule != MatchNone) {
			t.Errorf("MatchRegistry(%q,%q,%q) = %+v, want rule %s id %s", tc.name, tc.nameHash, tc.url, m, tc.rule, tc.id)
		}
	}
	// URL beats a name match elsewhere in the registry (rule-major walk).
	m := MatchRegistry("org", "exactname", "", "https://mcp.acme.io/mcp", reg)
	if m.Rule != MatchURL || m.ServerID != "s-url" {
		t.Fatalf("rule-major walk broken: %+v", m)
	}
}

func invItem(scope, name, transport, url, cmd string, args []string, cfg string, observed int64) InventoryItem {
	it := InventoryItem{
		Scope: scope, Transport: transport, Name: name, URL: url, Command: cmd, Args: args,
		ConfigPathHash: cfg, ObservedAt: observed, LastSeen: observed, NameHash: ServerNameHash("org", name),
	}
	it.Fingerprint = LocatorFingerprint(Locator{Transport: transport, URL: url, Command: cmd, Args: args, ConfigPathHash: cfg})
	return it
}

// TestDiff covers the dedupe (repeated stdio, same remote in two clients),
// registry filtering, the reduced (hash-only) row, pin supersession and the
// legacy pin candidate.
func TestDiff(t *testing.T) {
	reg := []RegistryServer{{ID: "s1", Name: "io.github.owner/github", Status: "approved"}}
	cfg := ConfigPathHash("/h/.claude.json")
	stdio := invItem("node-1", "files", "stdio", "", "npx", []string{"@x/files"}, cfg, 100)
	stdioAgain := stdio
	stdioAgain.ObservedAt, stdioAgain.LastSeen = 200, 200
	remoteA := invItem("node-1", "linear", "http", "https://mcp.linear.app/sse", "", nil, "", 150)
	remoteA.Client = "cursor"
	remoteB := remoteA
	remoteB.Client, remoteB.ObservedAt, remoteB.LastSeen, remoteB.FirstSeen = "claude-code", 90, 90, 90
	registered := invItem("node-1", "github", "stdio", "", "gh-mcp", nil, cfg, 100)
	reduced := InventoryItem{Scope: "node-2", Fingerprint: stdio.Fingerprint, NameHash: ServerNameHash("org", "secret-srv"), Transport: "stdio", ObservedAt: 300}
	notIngestible := InventoryItem{Scope: "node-2", Transport: "stdio"} // no fingerprint / hash
	pins := []PinItem{
		{Scope: "node-1", Name: "files", Client: "claude-code", Status: "pinned", FirstSeen: 10, LastSeen: 20}, // superseded by inventory
		{Scope: "node-3", Name: "legacy", Client: "codex", Status: "drifted", FirstSeen: 5, LastSeen: 50},
		{Scope: "node-3", Name: "github", Client: "codex", Status: "pinned"}, // registered (suffix)
		{Scope: "node-3", Name: " ", Client: "codex"},                        // no name
	}
	got := Diff("org", []InventoryItem{stdio, stdioAgain, remoteA, remoteB, registered, reduced, notIngestible}, pins, reg)
	if len(got) != 4 {
		t.Fatalf("Diff returned %d candidates, want 4: %+v", len(got), got)
	}
	// Sorted: guard_pin < mcp_inventory, then scope, then fingerprint.
	if got[0].Source != SourceGuardPin || got[0].Scope != "node-3" || got[0].Name != "legacy" || got[0].Transport != "" ||
		got[0].Evidence.PinStatus != "drifted" || got[0].FirstSeen != 5 || got[0].LastSeen != 50 ||
		got[0].Fingerprint != PinLocatorFingerprint("codex", "legacy") || got[0].NameHash != ServerNameHash("org", "legacy") {
		t.Fatalf("pin candidate = %+v", got[0])
	}
	byScopeName := map[string]Candidate{}
	for _, c := range got[1:] {
		if c.Source != SourceMCPInventory {
			t.Fatalf("unexpected source %+v", c)
		}
		byScopeName[c.Scope+"/"+c.Name] = c
	}
	files := byScopeName["node-1/files"]
	if files.FirstSeen != 100 || files.LastSeen != 200 || files.Command != "npx" || files.Evidence.ConfigPathHash != cfg {
		t.Fatalf("repeated stdio did not merge into one row: %+v", files)
	}
	linear := byScopeName["node-1/linear"]
	if linear.Client != "claude-code" || linear.FirstSeen != 90 || linear.LastSeen != 150 {
		t.Fatalf("same remote in two clients did not merge: %+v", linear)
	}
	red := byScopeName["node-2/"]
	if !red.HashOnly() || red.NameHash == "" || red.Fingerprint == "" || red.URL != "" || red.Command != "" || red.FirstSeen != 300 {
		t.Fatalf("reduced candidate = %+v", red)
	}
	// Order independence.
	again := Diff("org", []InventoryItem{reduced, remoteB, registered, stdioAgain, remoteA, stdio}, []PinItem{pins[3], pins[2], pins[1], pins[0]}, reg)
	if len(again) != len(got) {
		t.Fatalf("order changed the result: %d vs %d", len(again), len(got))
	}
	for i := range got {
		if again[i].Fingerprint != got[i].Fingerprint || again[i].FirstSeen != got[i].FirstSeen || again[i].LastSeen != got[i].LastSeen || again[i].Client != got[i].Client {
			t.Fatalf("order changed row %d: %+v vs %+v", i, again[i], got[i])
		}
	}
}

func TestPlanAdopt(t *testing.T) {
	reg := []RegistryServer{
		{ID: "s1", Name: "io.acme/remote", URL: "https://mcp.acme.io/mcp", Status: "approved"},
		{ID: "s2", Name: "io.github.owner/github", Status: "approved"},
	}
	fp := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name string
		in   AdoptInput
		code string
		plan AdoptPlan
	}{
		{"hash-only never adopts", AdoptInput{Status: StatusNew, NameHash: "h", Transport: "stdio", Fingerprint: fp}, RefuseNeedsNodeDisclosure, AdoptPlan{}},
		{"hash-only even with a requested name", AdoptInput{Status: StatusNew, NameHash: "h", Transport: "http", Fingerprint: fp, RequestedName: "io.x/y"}, RefuseNeedsNodeDisclosure, AdoptPlan{}},
		{"already adopted", AdoptInput{Status: StatusAdopted, Name: "x", Transport: "stdio", Command: "c"}, RefuseAlreadyAdopted, AdoptPlan{}},
		{"legacy pin has no locator", AdoptInput{Status: StatusNew, Source: SourceGuardPin, Name: "legacy"}, RefuseNeedsNodeDisclosure, AdoptPlan{}},
		{"remote without url", AdoptInput{Status: StatusNew, Name: "r", Transport: "http"}, RefuseNeedsNodeDisclosure, AdoptPlan{}},
		{"stdio without command", AdoptInput{Status: StatusNew, Name: "s", Transport: "stdio"}, RefuseNeedsNodeDisclosure, AdoptPlan{}},
		{"remote already registered by url", AdoptInput{Status: StatusNew, Name: "other", Transport: "http", URL: "https://mcp.acme.io/mcp/"}, RefuseAlreadyRegistered, AdoptPlan{}},
		{"url match refuses even with an explicit name", AdoptInput{Status: StatusNew, Name: "other", Transport: "http", URL: "https://mcp.acme.io/mcp", RequestedName: "io.x/dup"}, RefuseAlreadyRegistered, AdoptPlan{}},
		{"name match refuses by default", AdoptInput{Status: StatusNew, Name: "github", Transport: "stdio", Command: "gh"}, RefuseAlreadyRegistered, AdoptPlan{}},
		{
			"name match overridable by an explicit name",
			AdoptInput{Status: StatusNew, Name: "github", Transport: "stdio", Command: "gh", RequestedName: "io.acme/gh-local", Fingerprint: fp},
			"",
			AdoptPlan{Name: "io.acme/gh-local", Transport: RegistryNodeLocalStdio, NodeManaged: true},
		},
		{
			"remote adopts as streamable_http",
			AdoptInput{Status: StatusNew, Name: "linear", Transport: "http", URL: "https://mcp.linear.app/mcp", Fingerprint: fp},
			"",
			AdoptPlan{Name: "discovered.remote-abababab/linear", Transport: RegistryStreamableHTTP, URL: "https://mcp.linear.app/mcp"},
		},
		{
			"sse remote adopts as sse_legacy",
			AdoptInput{Status: StatusDismissed, Name: "old", Transport: "sse", URL: "https://old.example/sse", Fingerprint: fp},
			"",
			AdoptPlan{Name: "discovered.remote-abababab/old", Transport: RegistrySSELegacy, URL: "https://old.example/sse"},
		},
		{
			"stdio adopts as a node-relay managed entry",
			AdoptInput{Status: StatusReviewed, Name: "my files!", Transport: "stdio", Command: "npx", Fingerprint: fp},
			"",
			AdoptPlan{Name: "discovered.stdio-abababab/my-files-", Transport: RegistryNodeLocalStdio, NodeManaged: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, ref := PlanAdopt("org", tc.in, reg)
			if tc.code != "" {
				if ref == nil || ref.Code != tc.code {
					t.Fatalf("refusal = %v, want %s", ref, tc.code)
				}
				if ref.Error() == "" {
					t.Fatal("empty error text")
				}
				return
			}
			if ref != nil {
				t.Fatalf("refused: %v", ref)
			}
			if plan != tc.plan {
				t.Fatalf("plan = %+v, want %+v", plan, tc.plan)
			}
		})
	}
}

// registryNameRE mirrors regstore's reverse-DNS rule so a suggested name is
// always a valid registry name.
var registryNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func TestSuggestServerNameIsAValidRegistryName(t *testing.T) {
	fp := strings.Repeat("0f", 32)
	for _, name := range []string{"github", "my server", "@scope/pkg", "-dash", "", strings.Repeat("x", 400), "ünï"} {
		for _, class := range []string{ClassStdio, ClassRemote, ""} {
			got := SuggestServerName(class, fp, name)
			if !registryNameRE.MatchString(got) {
				t.Errorf("SuggestServerName(%q,%q) = %q is not a valid registry name", class, name, got)
			}
		}
	}
	if SuggestServerName(ClassStdio, "AAAA", "x") != "discovered.stdio-aaaa/x" {
		t.Fatalf("short / upper-case fingerprint: %q", SuggestServerName(ClassStdio, "AAAA", "x"))
	}
}
