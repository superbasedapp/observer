package sandboxopenshell

import (
	"slices"
	"strings"
	"testing"
)

func testLayout(t *testing.T) (GatewayIdentity, GatewayLayout) {
	t.Helper()
	id := testIdentity(t)
	l, err := LayoutFor("/home/dev/.observer/sandbox-openshell", "/run/user/1000", id)
	if err != nil {
		t.Fatal(err)
	}
	return id, l
}

func TestLayoutFor(t *testing.T) {
	t.Parallel()
	_, l := testLayout(t)
	if l.ConfigPath != "/home/dev/.observer/sandbox-openshell/gateway/gateway.toml" || l.DBPath != "/home/dev/.observer/sandbox-openshell/gateway/openshell.db" {
		t.Fatalf("state paths %+v", l)
	}
	if l.TLSDir != "/run/user/1000/observer-openshell-0123456789ab/tls" || l.CLIConfigHome != "/run/user/1000/observer-openshell-0123456789ab/cli" {
		t.Fatalf("runtime paths %+v", l)
	}
	for _, p := range []string{l.TLSDir, l.CLIConfigHome, l.XDGStateHome} {
		if !strings.HasPrefix(p, l.RuntimeDir+"/") {
			t.Fatalf("%s is outside the runtime dir: every secret-bearing path is in RAM", p)
		}
	}
	id := testIdentity(t)
	for _, bad := range [][2]string{
		{"relative", "/run/user/1000"},
		{"/a/../b", "/run/user/1000"},
		{"/a,b", "/run/user/1000"},
		{"/home/dev", "/"},
		{"/home/dev", ""},
		{"/home/dev", "/run/user/1000\n"},
		{"/home/\"dev", "/run/user/1000"},
	} {
		if _, err := LayoutFor(bad[0], bad[1], id); err == nil {
			t.Errorf("LayoutFor(%q, %q) accepted", bad[0], bad[1])
		}
	}
}

func TestRenderGatewayConfig(t *testing.T) {
	t.Parallel()
	out, err := RenderGatewayConfig(GatewayConfigInput{Name: "observer-0123456789ab"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[openshell]\nversion = 2\n",
		"name = \"observer-0123456789ab\"",
		"compute_driver = \"docker\"",
		"key_encryption_key_env = \"" + GatewayKEKEnv + "\"",
		"[openshell.drivers.docker]\nallow_driver_config = true\nenable_bind_mounts = true\n",
		// Finding F-027: the private gateway's own sandbox namespace, never
		// the package gateway's "default".
		"enable_bind_mounts = true\nsandbox_label = \"observer-0123456789ab\"\n",
		"[openshell.drivers.docker.resource_admission]\nenabled = false\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("config lacks %q:\n%s", want, out)
		}
	}
	// The OCSF export is off unless the one field names an endpoint.
	if strings.Contains(out, "otlp") {
		t.Fatalf("an empty endpoint must render no export:\n%s", out)
	}
	on, err := RenderGatewayConfig(GatewayConfigInput{Name: "observer-0123456789ab", OCSFEndpoint: "http://127.0.0.1:14317"})
	if err != nil || !strings.Contains(on, "[openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = \"http://127.0.0.1:14317\"\n") {
		t.Fatalf("OCSF export: %v\n%s", err, on)
	}
	if GatewayConfigDigest(on, "") == GatewayConfigDigest(out, "") || len(GatewayConfigDigest(out, "")) != 16 {
		t.Fatal("digest")
	}
	// A changed DOCKER_HOST is a changed start (audit finding O2-V2).
	if GatewayConfigDigest(out, "") == GatewayConfigDigest(out, "unix:///run/user/1000/docker.sock") {
		t.Fatal("DOCKER_HOST is not in the digest")
	}
	// No image key unless Images names one; the pinned references are
	// written under the Docker driver's table (ledger row OSH-48).
	if strings.Contains(out, "supervisor_image") || strings.Contains(out, "sandbox_runtime_image") {
		t.Fatalf("a zero Images must render no image key:\n%s", out)
	}
	pinned, _ := PinnedRuntimeImages(Version{Major: 0, Minor: 1, Patch: 6})
	img, err := RenderGatewayConfig(GatewayConfigInput{Name: "observer-0123456789ab", Images: pinned})
	if err != nil || !strings.Contains(img, "sandbox_label = \"observer-0123456789ab\"\nsupervisor_image = \""+pinned.Supervisor+"\"\nsandbox_runtime_image = \""+pinned.Sandbox+"\"\n\n[openshell.drivers.docker.resource_admission]") {
		t.Fatalf("pinned images: %v\n%s", err, img)
	}
	for _, bad := range []GatewayConfigInput{
		{Name: "observer-0123456789ab", Images: RuntimeImages{Supervisor: "ghcr.io/nvidia/openshell/supervisor:0.1.6"}},
		{Name: "observer-0123456789ab", Images: RuntimeImages{Sandbox: "x@sha256:" + strings.Repeat("a", 64) + "\"\n[evil]"}},
		{Name: "bad name"},
		{Name: "observer-0123456789ab", OCSFEndpoint: "http://collector.example.com:4317"},
		{Name: "observer-0123456789ab", OCSFEndpoint: "http://127.0.0.1"},
		{Name: "observer-0123456789ab", OCSFEndpoint: "grpc://127.0.0.1:4317"},
		{Name: "observer-0123456789ab", OCSFEndpoint: "http://127.0.0.1:4317/v1\"x"},
	} {
		if _, err := RenderGatewayConfig(bad); err == nil {
			t.Errorf("RenderGatewayConfig(%+v) accepted", bad)
		}
	}
}

func TestGatewayStartArgv(t *testing.T) {
	t.Parallel()
	id, l := testLayout(t)
	argv, err := GatewayStartArgv(GatewayStartInput{ID: id, Layout: l, GatewayBin: "/usr/bin/openshell-gateway", Port: 17701})
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "systemd-run" || argv[1] != "--user" {
		t.Fatalf("argv %v", argv)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--unit " + id.Unit,
		"--setenv=OPENSHELL_TELEMETRY_ENABLED=false", "--setenv=OPENSHELL_TELEMETRY_ENDPOINT=",
		"--setenv=OPENSHELL_LOCAL_TLS_DIR=" + l.TLSDir, "--setenv=XDG_CONFIG_HOME=" + l.CLIConfigHome,
		"--setenv=XDG_STATE_HOME=" + l.XDGStateHome,
		"-- /usr/bin/openshell-gateway --config " + l.ConfigPath,
		"--db-url sqlite:" + l.DBPath, "--bind-address 127.0.0.1", "--port 17701",
		"--health-port 0", "--metrics-port 0", "--enable-operator-auth false", "--compute-driver docker",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("start argv lacks %q: %s", want, joined)
		}
	}
	// The key-encryption key reaches the unit through its RAM-dir
	// EnvironmentFile only: no --setenv of its name, with or without a
	// value (systemd 245 refuses the name-only form; audit finding O2-A6).
	if !slices.Contains(argv, "--property=EnvironmentFile="+l.EnvFile) || !strings.HasPrefix(l.EnvFile, l.RuntimeDir+"/") {
		t.Fatalf("the KEK must come from the RAM dir's env file: %v", argv)
	}
	for _, a := range argv {
		if strings.Contains(a, GatewayKEKEnv) {
			t.Fatalf("the KEK variable is on the command line: %q", a)
		}
	}
	if !slices.Contains(argv, "--property=StartLimitBurst=5") || slices.Contains(argv, "--setenv=DOCKER_HOST=") || slices.Contains(argv, "--collect") {
		t.Fatalf("start limit or a stray DOCKER_HOST: %v", argv)
	}
	dh, err := GatewayStartArgv(GatewayStartInput{ID: id, Layout: l, GatewayBin: "/usr/bin/openshell-gateway", Port: 17701, DockerHost: "unix:///run/user/1000/docker.sock"})
	if err != nil || !slices.Contains(dh, "--setenv=DOCKER_HOST=unix:///run/user/1000/docker.sock") {
		t.Fatalf("DOCKER_HOST pass-through: %v %v", dh, err)
	}
	if _, err := GatewayStartArgv(GatewayStartInput{ID: id, Layout: l, GatewayBin: "/usr/bin/openshell-gateway", Port: 17701, DockerHost: "tcp://x y"}); err == nil {
		t.Fatal("a DOCKER_HOST with a space was accepted")
	}

	unset := ""
	for _, a := range argv {
		if v, ok := strings.CutPrefix(a, "--property=UnsetEnvironment="); ok {
			unset = v
		}
	}
	for _, v := range []string{"OPENSHELL_DISABLE_TLS", "OPENSHELL_OIDC_ISSUER", "OPENSHELL_GATEWAY_CREDENTIAL_KEY_ENCRYPTION_KEY"} {
		if !strings.Contains(unset, v) {
			t.Fatalf("the unit must unset %s: %q", v, unset)
		}
	}
	for _, set := range []string{"OPENSHELL_TELEMETRY_ENABLED", "OPENSHELL_LOCAL_TLS_DIR", "XDG_CONFIG_HOME", "XDG_STATE_HOME", GatewayKEKEnv} {
		if slices.Contains(strings.Fields(unset), set) {
			t.Fatalf("the unit unsets %s, which it sets itself", set)
		}
	}
	bad := []GatewayStartInput{
		{ID: GatewayIdentity{Name: id.Name, Unit: "sshd.service"}, Layout: l, GatewayBin: "/usr/bin/openshell-gateway", Port: 1},
		{ID: id, Layout: l, GatewayBin: "openshell-gateway", Port: 1},
		{ID: id, Layout: l, GatewayBin: "/usr/bin/openshell-gateway", Port: 0},
		{ID: id, Layout: GatewayLayout{}, GatewayBin: "/usr/bin/openshell-gateway", Port: 1},
	}
	for _, in := range bad {
		if _, err := GatewayStartArgv(in); err == nil {
			t.Errorf("GatewayStartArgv(%+v) accepted", in)
		}
	}
}

func TestGatewayToolArgv(t *testing.T) {
	t.Parallel()
	id, l := testLayout(t)
	if got := GenerateCertsArgv(l); !slices.Equal(got, []string{"openshell-gateway", "generate-certs", "--output-dir", l.TLSDir, "--server-san", "127.0.0.1"}) {
		t.Fatalf("generate-certs %v", got)
	}
	add, err := GatewayAddArgv(id, 17701)
	if err != nil || !slices.Equal(add, []string{"openshell", "gateway", "add", "https://127.0.0.1:17701", "--local", "--name", id.Name}) {
		t.Fatalf("gateway add %v %v", add, err)
	}
	env := GatewayToolEnv(l)
	if !slices.Contains(env, "XDG_CONFIG_HOME="+l.CLIConfigHome) || !slices.Contains(env, "OPENSHELL_LOCAL_TLS_DIR="+l.TLSDir) {
		t.Fatalf("tool env %v", env)
	}
	for _, verb := range []string{"is-active", "stop", "reset-failed"} {
		if a, err := UnitArgv(verb, id.Unit); err != nil || a[3] != id.Unit {
			t.Fatalf("UnitArgv(%s): %v %v", verb, a, err)
		}
	}
	for _, bad := range [][2]string{{"start", id.Unit}, {"stop", "default.target"}, {"stop", "observer-openshell-gateway-x.service"}} {
		if _, err := UnitArgv(bad[0], bad[1]); err == nil {
			t.Errorf("UnitArgv(%q, %q) accepted", bad[0], bad[1])
		}
	}
	for in, want := range map[string]bool{"running\n": true, "degraded": true, "starting": true, "offline": false, "": false, "Failed to connect to bus": false} {
		if ParseSupervisor(in) != want {
			t.Errorf("ParseSupervisor(%q) != %v", in, want)
		}
	}
}

func TestTargetConfigHome(t *testing.T) {
	t.Parallel()
	tg := Target{Gateway: "observer-0123456789ab", ConfigHome: "/run/user/1000/observer-openshell-0123456789ab/cli"}
	env, ok := TargetEnv(tg)
	if !ok || !slices.Equal(env, []string{"XDG_CONFIG_HOME=" + tg.ConfigHome}) {
		t.Fatalf("env %v", env)
	}
	if env, ok := TargetEnv(Target{Gateway: "x"}); !ok || env != nil {
		t.Fatal("an external target runs with the user's own registry")
	}
	argv, err := StatusArgv(tg)
	if err != nil || strings.Contains(strings.Join(argv, " "), tg.ConfigHome) {
		t.Fatalf("the config home is an environment value, never a flag: %v %v", argv, err)
	}
	if _, err := ListArgv(Target{Gateway: "x", ConfigHome: "relative/dir"}, []Label{{LabelInstall, "o01234567o"}}); err == nil {
		t.Fatal("a relative config home was accepted")
	}
}

func TestGatewayEnvFile(t *testing.T) {
	t.Parallel()
	got, err := GatewayEnvFile("c2VudGluZWwtMDAwMA==")
	if err != nil || got != GatewayKEKEnv+"=c2VudGluZWwtMDAwMA==\n" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"", "a b", "x\ny=1", `"q"`} {
		if _, err := GatewayEnvFile(bad); err == nil {
			t.Errorf("GatewayEnvFile(%q) accepted", bad)
		}
	}
}

// TestSandboxLabelFor (findings OC2-A5 and OC2-V1): the gateway's own name
// unless a run is recorded on it, when the namespace it was started with
// is kept, so no start strands a box beyond the reaper's reach. A record
// with no label field is matched against its digest: the first build that
// set the namespace without recording it ran under the own name, an older
// one in the driver default (which renders no key, so such a gateway
// keeps the exact config it started with).
func TestSandboxLabelFor(t *testing.T) {
	t.Parallel()
	const name = "observer-0123456789ab"
	digestFor := func(label string) string {
		r, err := RenderGatewayConfig(GatewayConfigInput{Name: name, SandboxLabel: label})
		if err != nil {
			t.Fatal(err)
		}
		return GatewayConfigDigest(r, "unix:///run/d.sock")
	}
	ownDigest, defDigest := digestFor(name), digestFor(DefaultSandboxLabel)
	for _, tc := range []struct {
		why  string
		rec  *GatewayRecord
		runs int
		want string
	}{
		{"no record", nil, 0, name},
		{"no record, runs", nil, 3, name},
		{"no run recorded", &GatewayRecord{}, 0, name},
		{"no label, no digest", &GatewayRecord{}, 1, DefaultSandboxLabel},
		{"no label, pre-namespace digest", &GatewayRecord{ConfigDigest: defDigest}, 1, DefaultSandboxLabel},
		{"no label, own-name digest (first OC2 build)", &GatewayRecord{ConfigDigest: ownDigest}, 1, name},
		{"no label, a digest matching neither", &GatewayRecord{ConfigDigest: "feedface"}, 1, DefaultSandboxLabel},
		{"recorded own label", &GatewayRecord{SandboxLabel: name}, 2, name},
		{"recorded default label", &GatewayRecord{SandboxLabel: DefaultSandboxLabel, ConfigDigest: ownDigest}, 2, DefaultSandboxLabel},
		{"recorded default label, no run", &GatewayRecord{SandboxLabel: DefaultSandboxLabel}, 0, name},
	} {
		if got := SandboxLabelFor(name, tc.rec, tc.runs, digestFor); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.why, got, tc.want)
		}
	}
	if got := SandboxLabelFor(name, &GatewayRecord{ConfigDigest: ownDigest}, 1, nil); got != DefaultSandboxLabel {
		t.Errorf("no digest func: %q", got)
	}
	def, err := RenderGatewayConfig(GatewayConfigInput{Name: name, SandboxLabel: DefaultSandboxLabel})
	if err != nil || strings.Contains(def, "sandbox_label") {
		t.Fatalf("the driver default renders a key: %v\n%s", err, def)
	}
	own, _ := RenderGatewayConfig(GatewayConfigInput{Name: name})
	if GatewayConfigDigest(def, "") == GatewayConfigDigest(own, "") {
		t.Fatal("the namespace is not part of the config digest")
	}
	if _, err := RenderGatewayConfig(GatewayConfigInput{Name: name, SandboxLabel: "bad label"}); err == nil {
		t.Fatal("a bad label accepted")
	}
}

// TestUnitConfigPath: one case per shape of `systemctl --user show -p
// ExecStart --value UNIT` (ledger row OSH-42).
func TestUnitConfigPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, out, want string
		ok              bool
	}{
		{"a running unit", "{ path=/usr/bin/openshell-gateway ; argv[]=/usr/bin/openshell-gateway --config /s/gateway/gateway.toml --db-url sqlite:/s/gateway/openshell.db ; ignore_errors=no ; start_time=[n/a] ; pid=7 ; code=(null) ; status=0/0 }\n", "/s/gateway/gateway.toml", true},
		{"not loaded", "\n", "", false},
		{"no --config", "{ path=/x ; argv[]=/x --port 1 ; ignore_errors=no }", "", false},
		{"--config last", "{ path=/x ; argv[]=/x --config ; ignore_errors=no }", "", false},
		{"--config only after the argv", "{ path=/x ; argv[]=/x ; ignore_errors=no --config /y }", "", false},
	} {
		got, ok := UnitConfigPath(tc.out)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got %q %v", tc.name, got, ok)
		}
	}
	if a, err := UnitShowArgv("observer-openshell-gateway-0123456789ab.service"); err != nil || strings.Join(a, " ") != "systemctl --user show -p ExecStart --value observer-openshell-gateway-0123456789ab.service" {
		t.Fatalf("got %v %v", a, err)
	}
	if _, err := UnitShowArgv("ssh.service"); err == nil {
		t.Fatal("another unit accepted")
	}
}
