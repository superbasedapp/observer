package sandboxoci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// cacheOffGrid is PlanToolDelivery's every answer over the five facts the
// table read before the install step, recorded on the base a4acb0d73 (lane
// SBX-P3C): with InstallCache off the table must answer each exactly so.
var cacheOffGrid = []struct {
	host, interp           string
	hasInterp, hasTool, sp bool
	pick, code, reason     string
}{
	{"", "", false, false, false, "", "tool_unavailable_in_image", "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)"},
	{"", "", false, false, true, "", "tool_unavailable_in_image", "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)"},
	{"", "", false, true, false, "", "tool_unavailable_in_image", "the image has its own copy of the tool, which may be a different version from the host's; it never runs on the real tool state, only on a projected one (the oci-runsc row), so it is not used here"},
	{"", "", false, true, true, "image_installed", "available", ""},
	{"", "", true, false, false, "", "tool_unavailable_in_image", "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)"},
	{"", "", true, false, true, "", "tool_unavailable_in_image", "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)"},
	{"", "", true, true, false, "", "tool_unavailable_in_image", "the image has its own copy of the tool, which may be a different version from the host's; it never runs on the real tool state, only on a projected one (the oci-runsc row), so it is not used here"},
	{"", "", true, true, true, "image_installed", "available", ""},
	{"", "/lib/ld-musl-x86_64.so.1", false, false, false, "", "tool_unavailable_in_image", "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)"},
	{"", "/lib/ld-musl-x86_64.so.1", false, false, true, "", "tool_unavailable_in_image", "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)"},
	{"", "/lib/ld-musl-x86_64.so.1", false, true, false, "", "tool_unavailable_in_image", "the image has its own copy of the tool, which may be a different version from the host's; it never runs on the real tool state, only on a projected one (the oci-runsc row), so it is not used here"},
	{"", "/lib/ld-musl-x86_64.so.1", false, true, true, "image_installed", "available", ""},
	{"", "/lib/ld-musl-x86_64.so.1", true, false, false, "", "tool_unavailable_in_image", "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)"},
	{"", "/lib/ld-musl-x86_64.so.1", true, false, true, "", "tool_unavailable_in_image", "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)"},
	{"", "/lib/ld-musl-x86_64.so.1", true, true, false, "", "tool_unavailable_in_image", "the image has its own copy of the tool, which may be a different version from the host's; it never runs on the real tool state, only on a projected one (the oci-runsc row), so it is not used here"},
	{"", "/lib/ld-musl-x86_64.so.1", true, true, true, "image_installed", "available", ""},
	{"/usr/bin/tool", "", false, false, false, "host_bind", "available", ""},
	{"/usr/bin/tool", "", false, false, true, "host_bind", "available", ""},
	{"/usr/bin/tool", "", false, true, false, "host_bind", "available", ""},
	{"/usr/bin/tool", "", false, true, true, "host_bind", "available", ""},
	{"/usr/bin/tool", "", true, false, false, "host_bind", "available", ""},
	{"/usr/bin/tool", "", true, false, true, "host_bind", "available", ""},
	{"/usr/bin/tool", "", true, true, false, "host_bind", "available", ""},
	{"/usr/bin/tool", "", true, true, true, "host_bind", "available", ""},
	{"/usr/bin/tool", "/lib/ld-musl-x86_64.so.1", false, false, false, "", "tool_unavailable_in_image", "the image cannot run the host's tool: its loader /lib/ld-musl-x86_64.so.1 is not in the image; use an image with the same C library as this host (glibc for most distributions), or wait for the first-start install (needs the egress domain allow-list, G23)"},
	{"/usr/bin/tool", "/lib/ld-musl-x86_64.so.1", false, false, true, "", "tool_unavailable_in_image", "the image cannot run the host's tool: its loader /lib/ld-musl-x86_64.so.1 is not in the image; use an image with the same C library as this host (glibc for most distributions), or wait for the first-start install (needs the egress domain allow-list, G23)"},
	{"/usr/bin/tool", "/lib/ld-musl-x86_64.so.1", false, true, false, "", "tool_unavailable_in_image", "the image has its own copy of the tool, which may be a different version from the host's; it never runs on the real tool state, only on a projected one (the oci-runsc row), so it is not used here"},
	{"/usr/bin/tool", "/lib/ld-musl-x86_64.so.1", false, true, true, "image_installed", "available", ""},
	{"/usr/bin/tool", "/lib/ld-musl-x86_64.so.1", true, false, false, "host_bind", "available", ""},
	{"/usr/bin/tool", "/lib/ld-musl-x86_64.so.1", true, false, true, "host_bind", "available", ""},
	{"/usr/bin/tool", "/lib/ld-musl-x86_64.so.1", true, true, false, "host_bind", "available", ""},
	{"/usr/bin/tool", "/lib/ld-musl-x86_64.so.1", true, true, true, "host_bind", "available", ""},
}

func TestToolDeliveryCacheOffUnchanged(t *testing.T) {
	t.Parallel()
	for _, g := range cacheOffGrid {
		// The install facts are set but the key is off: they must not matter.
		f := ToolFacts{
			HostBinary: g.host, Interp: g.interp, ImageHasInterp: g.hasInterp, ImageHasTool: g.hasTool, StateProjected: g.sp,
			InstallSourceKnown: true, InstallVersion: "1.2.3", ImageHasRuntime: true,
		}
		d, v := PlanToolDelivery(f)
		if string(d) != g.pick || v.Code != g.code || v.Reason != g.reason {
			t.Errorf("%+v: got %q %q %q", g, d, v.Code, v.Reason)
		}
	}
}

func TestToolDeliveryCacheRows(t *testing.T) {
	t.Parallel()
	musl := ToolFacts{
		HostBinary: "/usr/bin/node", Interp: "/lib64/ld-linux-x86-64.so.2", InstallCache: true,
		InstallSourceKnown: true, InstallVersion: "2.1.309", ImageHasRuntime: true,
	}
	cases := []struct {
		name string
		edit func(f *ToolFacts)
		pick Delivery
		code string
	}{
		{"install cache", func(*ToolFacts) {}, DeliveryInstallCache, VerdictAvailable},
		{"source unknown", func(f *ToolFacts) { f.InstallSourceKnown = false }, "", VerdictInstallSourceUnknown},
		{"version unknown", func(f *ToolFacts) { f.InstallVersion = "" }, "", VerdictInstallVersionUnknown},
		{"version not plain", func(f *ToolFacts) { f.InstallVersion = "latest" }, "", VerdictInstallVersionUnknown},
		{"runtime missing", func(f *ToolFacts) { f.ImageHasRuntime = false }, "", VerdictInstallRuntimeMissing},
		{"scripts required", func(f *ToolFacts) { f.InstallNeedsScripts = true }, "", VerdictInstallScriptsRequired},
		{"no host tool", func(f *ToolFacts) { f.HostBinary, f.Interp, f.InstallVersion = "", "", "" }, "", VerdictInstallVersionUnknown},
		{"host bind still wins", func(f *ToolFacts) { f.ImageHasInterp = true }, DeliveryHostBind, VerdictAvailable},
		{"image copy on a same-kernel row is projected", func(f *ToolFacts) { f.ImageHasTool = true }, DeliveryImageInstalled, VerdictAvailable},
	}
	for _, c := range cases {
		f := musl
		c.edit(&f)
		d, v := PlanToolDelivery(f)
		if d != c.pick || v.Code != c.code {
			t.Errorf("%s: got %q %v", c.name, d, v)
		}
	}
}

func TestProjectsState(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d     Delivery
		cross bool
		want  bool
	}{
		{DeliveryHostBind, false, false},
		{DeliveryInstallCache, false, false},
		{DeliveryImageInstalled, false, true},
		{DeliveryHostBind, true, true},
		{DeliveryInstallCache, true, true},
		{DeliveryImageInstalled, true, true},
	}
	for _, c := range cases {
		if got := ProjectsState(c.d, c.cross); got != c.want {
			t.Errorf("ProjectsState(%s, %v) = %v", c.d, c.cross, got)
		}
	}
}

func testInstallPlan() InstallCreatePlan {
	return InstallCreatePlan{
		RunID: "run0000000000000001", InstallID: "inst000000000001",
		Image:            "node@sha256:" + strings.Repeat("b", 64),
		EntrypointPrefix: []string{"/usr/bin/observer", "sandbox-oci-install", "--gateway", "/tmp/.observer-sandbox-net/gateway.sock", "--port", "3128", "--"},
		ObserverBin:      "/usr/bin/observer", SockDir: "/tmp/observer-sbx-inst-1", GuestSockDir: "/tmp/.observer-sandbox-net",
		Volume:  CacheVolumeName("inst000000000001", "sha256:"+strings.Repeat("b", 64), "tool-a", "2.1.309"),
		Source:  InstallSource{Kind: "npm", Package: "@vendor/tool-a", Bin: "tool-a", Hosts: []string{"registry.npmjs.org"}},
		Version: "2.1.309", User: UserPlan{Row: "rootful", User: "1000:1000"}, Engine: EngineDocker,
		EngineSocket: "/run/docker.sock", ObserverDir: "/home/dev/.observer",
	}
}

// TestBuildInstallCreateGolden pins the setup container's create body: no
// workspace, no tool state, no credential variable, no host environment,
// a read-only root, the three mounts only (the observer binary and the
// gateway socket directory read-only, the cache volume read-write), no
// network.
func TestBuildInstallCreateGolden(t *testing.T) {
	t.Parallel()
	name, body, err := BuildInstallCreate(testInstallPlan())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.MarshalIndent(map[string]any{"name": name, "body": body}, "", "  ")
	gp := filepath.Join("testdata", "install_create.golden")
	if os.Getenv("SBO_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(gp, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(gp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
		t.Fatalf("the setup container's create body changed:\n%s", got)
	}
	for _, kv := range body.Env {
		k, _, _ := strings.Cut(kv, "=")
		for _, bad := range []string{"KEY", "TOKEN", "SECRET", "ANTHROPIC", "OPENAI", "SSH_AUTH_SOCK", "PATH"} {
			if strings.Contains(strings.ToUpper(k), bad) {
				t.Errorf("the setup container's environment carries %s", kv)
			}
		}
	}
	if !body.HostConfig.ReadonlyRootfs || body.HostConfig.NetworkMode != NetworkNone || len(body.HostConfig.Mounts) != 3 {
		t.Fatalf("hardening: %+v", body.HostConfig)
	}
	var vols, rw int
	for _, m := range body.HostConfig.Mounts {
		if m.Type == "volume" {
			vols++
		}
		if !m.ReadOnly {
			rw++
		}
	}
	if vols != 1 || rw != 1 {
		t.Fatalf("mounts: %+v", body.HostConfig.Mounts)
	}
	if !slices.Equal(body.Entrypoint[len(body.Entrypoint)-1:], []string{"@vendor/tool-a@2.1.309"}) {
		t.Fatalf("the install is not pinned to the host's version: %v", body.Entrypoint)
	}
	if !slices.Contains(body.Entrypoint, "--ignore-scripts") {
		t.Fatalf("the install runs package scripts: %v", body.Entrypoint)
	}
}

func TestBuildInstallCreateRefuses(t *testing.T) {
	t.Parallel()
	cases := map[string]func(p *InstallCreatePlan){
		"kind":          func(p *InstallCreatePlan) { p.Source.Kind = "script" },
		"package":       func(p *InstallCreatePlan) { p.Source.Package = "tool; rm -rf /" },
		"version":       func(p *InstallCreatePlan) { p.Version = "latest" },
		"version flag":  func(p *InstallCreatePlan) { p.Version = "1.2.3 --unsafe-perm" },
		"tag image":     func(p *InstallCreatePlan) { p.Image = "node:22" },
		"volume":        func(p *InstallCreatePlan) { p.Volume = "my-volume" },
		"engine socket": func(p *InstallCreatePlan) { p.SockDir = "/run" },
		"observer dir":  func(p *InstallCreatePlan) { p.SockDir = "/home/dev" },
		"root":          func(p *InstallCreatePlan) { p.User = UserPlan{Row: "rootful", User: "0:0"} },
		"no user":       func(p *InstallCreatePlan) { p.User = UserPlan{} },
		"needs scripts": func(p *InstallCreatePlan) { p.Source.NeedsScripts = true },
	}
	for name, edit := range cases {
		p := testInstallPlan()
		edit(&p)
		if _, _, err := BuildInstallCreate(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCacheVolumeNameAndLabels(t *testing.T) {
	t.Parallel()
	d := "sha256:" + strings.Repeat("c", 64)
	a := CacheVolumeName("inst000000000001", d, "tool-a", "1.0.0")
	if !strings.HasPrefix(a, CacheVolumePrefix+"inst0000-") || strings.Contains(a, "tool-a") {
		t.Fatalf("name %q", a)
	}
	for _, other := range []string{
		CacheVolumeName("inst000000000002", d, "tool-a", "1.0.0"),
		CacheVolumeName("inst000000000001", "sha256:"+strings.Repeat("d", 64), "tool-a", "1.0.0"),
		CacheVolumeName("inst000000000001", d, "tool-b", "1.0.0"),
		CacheVolumeName("inst000000000001", d, "tool-a", "1.0.1"),
	} {
		if other == a {
			t.Fatalf("two keys share the name %q", a)
		}
	}
	l := CacheLabels("inst000000000001", d, "tool-a", "1.0.0", "@vendor/tool-a")
	if l[LabelRole] != RoleToolCache || l[LabelInstall] != "inst000000000001" || l[LabelCacheImage] != d || l[LabelCacheVersion] != "1.0.0" {
		t.Fatalf("labels %v", l)
	}
	f := CacheFilter("inst000000000001", d, "tool-a")["label"]
	if len(f) != 4 || !slices.Contains(f, LabelCacheTool+"=tool-a") {
		t.Fatalf("filter %v", f)
	}
	if dg, ok := ImageDigestOf("node@" + d); !ok || dg != d {
		t.Fatalf("digest %q %v", dg, ok)
	}
	if _, ok := ImageDigestOf("node:22"); ok {
		t.Fatal("a tag has no digest")
	}
}

func TestClassifyCache(t *testing.T) {
	t.Parallel()
	d := "sha256:" + strings.Repeat("e", 64)
	inst := "inst000000000001"
	cur := CacheVolumeName(inst, d, "tool-a", "2.0.0")
	old := CacheVolumeName(inst, d, "tool-a", "1.0.0")
	vol := func(name, version string) CacheVolumeFact {
		return CacheVolumeFact{Name: name, Labels: CacheLabels(inst, d, "tool-a", version, "@vendor/tool-a")}
	}
	foreign := CacheVolumeFact{Name: CacheVolumeName("inst000000000002", d, "tool-a", "2.0.0"), Labels: CacheLabels("inst000000000002", d, "tool-a", "2.0.0", "x")}
	all := func(string) bool { return true }
	none := func(string) bool { return false }
	cases := []struct {
		name  string
		vols  []CacheVolumeFact
		done  func(string) bool
		state CacheState
		other int
	}{
		{"absent", nil, all, CacheAbsent, 0},
		{"current", []CacheVolumeFact{vol(cur, "2.0.0")}, all, CacheCurrent, 0},
		{"unfinished is not a cache", []CacheVolumeFact{vol(cur, "2.0.0")}, none, CacheStale, 1},
		{"stale", []CacheVolumeFact{vol(old, "1.0.0")}, all, CacheStale, 1},
		{"current plus an old one", []CacheVolumeFact{vol(cur, "2.0.0"), vol(old, "1.0.0")}, all, CacheCurrent, 1},
		{"another install's volume is never considered", []CacheVolumeFact{foreign}, all, CacheAbsent, 0},
		{"a relabelled name is not current", []CacheVolumeFact{{Name: cur, Labels: CacheLabels(inst, d, "tool-a", "9.9.9", "x")}}, all, CacheStale, 1},
	}
	for _, c := range cases {
		v := ClassifyCache(c.vols, c.done, inst, d, "tool-a", "2.0.0")
		if v.State != c.state || len(v.Others) != c.other {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
}

// TestInstallReadBackMatchesTheBody: the setup container read back from its
// own create body passes, and a weakened one is refused.
func TestInstallReadBackMatchesTheBody(t *testing.T) {
	t.Parallel()
	p := testInstallPlan()
	_, body, err := BuildInstallCreate(p)
	if err != nil {
		t.Fatal(err)
	}
	facts := InspectFacts{
		User: body.User, Labels: body.Labels, NetworkMode: body.HostConfig.NetworkMode, CapDrop: body.HostConfig.CapDrop,
		SecurityOpt: body.HostConfig.SecurityOpt, ReadonlyRootfs: true, Runtime: "runc", Tmpfs: body.HostConfig.Tmpfs,
		IpcMode: "private", PidsLimit: &body.HostConfig.PidsLimit,
	}
	for _, m := range body.HostConfig.Mounts {
		facts.Mounts = append(facts.Mounts, MountFact{Type: m.Type, Name: m.Source, Source: m.Source, Destination: m.Target, RW: !m.ReadOnly})
	}
	id := Identity{Engine: EngineDocker, Mode: ModeRootful}
	if v := ReadBack(ReadBackInput{Identity: id, Plan: InstallReadBackPlan(p), Facts: facts}); !v.OK() {
		t.Fatalf("read-back: %v", v)
	}
	facts.Mounts = append(facts.Mounts, MountFact{Type: "bind", Source: "/home/dev", Destination: "/home/dev", RW: true})
	if v := ReadBack(ReadBackInput{Identity: id, Plan: InstallReadBackPlan(p), Facts: facts}); v.OK() {
		t.Fatal("an unplanned workspace bind passed")
	}
}

func TestInstallEnvIsTheAllowList(t *testing.T) {
	t.Parallel()
	env := InstallEnv(3128)
	if !slices.Contains(env, "HTTPS_PROXY=http://127.0.0.1:3128") || len(env) != 10 {
		t.Fatalf("env %v", env)
	}
	if rt, ok := InstallerRuntime("npm"); !ok || !slices.Equal(rt, []string{"node", "npm"}) {
		t.Fatalf("npm runtime %v", rt)
	}
	if _, ok := InstallerRuntime("script"); ok {
		t.Fatal("a script installer is not offered")
	}
	if CacheBinDir("npm") != ToolCacheMount+"/bin" {
		t.Fatal(CacheBinDir("npm"))
	}
}

func TestPlanSeeds(t *testing.T) {
	t.Parallel()
	proj, err := PlanProjection("/m/r1.state", "/home/dev", []string{".claude", ".claude.json"})
	if err != nil {
		t.Fatal(err)
	}
	copies, roots, err := PlanSeeds(proj, "/home/dev", []string{".claude/CLAUDE.md"}, []string{".claude/projects"})
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) != 1 || copies[0] != (SeedCopy{From: "/home/dev/.claude/CLAUDE.md", To: "/m/r1.state/0/CLAUDE.md"}) {
		t.Fatalf("copies %+v", copies)
	}
	if len(roots) != 1 || roots[0] != (TranscriptRoot{Host: "/m/r1.state/0/projects", Box: "/home/dev/.claude/projects"}) {
		t.Fatalf("roots %+v", roots)
	}
	for _, bad := range []string{"../etc/passwd", "/etc/passwd", ".claude/../x", ".config/x", ".claude", ""} {
		if _, _, err := PlanSeeds(proj, "/home/dev", []string{bad}, nil); err == nil {
			t.Errorf("seed %q accepted", bad)
		}
	}
}
