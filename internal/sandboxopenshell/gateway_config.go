package sandboxopenshell

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// gateway_config.go renders the managed gateway's fixed inputs: where its
// files live, its config file, and the argv of every program its lifecycle
// runs. Grounded on OpenShell v0.1.6 (tag ac7f615cd, read in lane O2):
//
//   - the package's own user service (deploy/deb/openshell-gateway.service)
//     runs `openshell-gateway generate-certs --output-dir
//     $OPENSHELL_LOCAL_TLS_DIR` and then `openshell-gateway` with that
//     variable set; the gateway reads its mTLS and sandbox-JWT material
//     from that dir (crates/openshell-server/src/defaults.rs);
//   - generate-certs also copies the client bundle into
//     $XDG_CONFIG_HOME/openshell/gateways/openshell/mtls, and `openshell
//     gateway add --local` imports the client bundle from
//     $OPENSHELL_LOCAL_TLS_DIR into $XDG_CONFIG_HOME/openshell/gateways/
//     <name>/mtls (crates/openshell-cli/src/commands/gateway.rs), so the
//     CLI and the gateway find each other only through those two
//     variables, which Observer points at its own private dirs;
//   - [openshell.gateway.credential_storage] key_encryption_key_env loads
//     the credential store's key from a variable (base64 of 32 bytes)
//     instead of creating key-encryption-key.bin under $XDG_STATE_HOME
//     (crates/openshell-driver-db-credstore, the O0-L2 stray file);
//   - every flag beats its variable (the server's clap args), so the
//     security-relevant settings go on the command line, and the
//     variables the user manager could pass in from the user's own
//     environment are unset on the unit;
//   - GetProviderCredentials (risk RK-20) requires an operator
//     certificate, and operator authentication is off unless
//     --enable-operator-auth is set; the unit pins it false, the client
//     certificate generate-certs mints is a user certificate (OU
//     openshell-user), and Observer never registers a provider (every box
//     is created with --no-auto-providers), so the daemon never calls it
//     and has nothing it could retrieve.

// GatewayProgram is the OpenShell gateway binary's name.
const GatewayProgram = "openshell-gateway"

// GatewayLayout is where the managed gateway's files live. State is
// persistent and holds no secret (its config, its database of sandboxes,
// the record, the lock, the keystore's fallback dir); Runtime is a private
// RAM dir (GatewayRuntimeFS) that holds the PKI and the CLI registry only
// while the gateway runs.
type GatewayLayout struct {
	// StateDir is <row state dir>/gateway.
	StateDir   string
	ConfigPath string
	DBPath     string
	RecordPath string
	LockPath   string
	// CustodyPath records which custody the held record set was saved
	// under (CustodyKeychain or CustodyOwnerFile; audit finding O2-A5).
	CustodyPath string
	// KeysDir is the keystore's owner-only file store (CustodyOwnerFile).
	KeysDir string
	// RuntimeDir is $XDG_RUNTIME_DIR/observer-openshell-<install>.
	RuntimeDir string
	// TLSDir is the gateway's OPENSHELL_LOCAL_TLS_DIR (the restored PKI).
	TLSDir string
	// CLIConfigHome is the XDG_CONFIG_HOME every openshell call about the
	// managed gateway runs with (its private registry).
	CLIConfigHome string
	// XDGStateHome is the gateway's XDG_STATE_HOME: anything it writes
	// there on its own lands in RAM, never on disk.
	XDGStateHome string
	// EnvFile is the unit's EnvironmentFile (0600, in the RAM dir): the
	// key-encryption key, read by the user manager at each start and
	// removed when the gateway stops (audit finding O2-A6).
	EnvFile string
}

// safePath reports whether p is an absolute, clean path a TOML string, a
// systemd property and a --mount-free argv can carry.
func safePath(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p && !strings.ContainsAny(p, "\"'\\,=;$`") &&
		strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

// LayoutFor returns the managed gateway's layout for the row's state dir,
// the user's runtime dir ($XDG_RUNTIME_DIR) and the install's identity.
func LayoutFor(rowStateDir, runtimeDir string, id GatewayIdentity) (GatewayLayout, error) {
	if !safePath(rowStateDir) {
		return GatewayLayout{}, fmt.Errorf("sandboxopenshell.LayoutFor: state dir %q is not an absolute, clean path free of quoting characters", rowStateDir)
	}
	if !safePath(runtimeDir) || runtimeDir == "/" {
		return GatewayLayout{}, fmt.Errorf("sandboxopenshell.LayoutFor: runtime dir %q is not an absolute, clean path free of quoting characters", runtimeDir)
	}
	if !gatewayNameRE.MatchString(id.Name) {
		return GatewayLayout{}, fmt.Errorf("sandboxopenshell.LayoutFor: gateway name %q is not a name", id.Name)
	}
	st := path.Join(rowStateDir, "gateway")
	rt := path.Join(runtimeDir, "observer-openshell-"+strings.TrimPrefix(id.Name, "observer-"))
	return GatewayLayout{
		StateDir:      st,
		ConfigPath:    path.Join(st, "gateway.toml"),
		DBPath:        path.Join(st, "openshell.db"),
		RecordPath:    path.Join(st, "gateway.json"),
		LockPath:      path.Join(st, "lock"),
		CustodyPath:   path.Join(st, "custody"),
		KeysDir:       path.Join(st, "keys"),
		EnvFile:       path.Join(rt, "gateway.env"),
		RuntimeDir:    rt,
		TLSDir:        path.Join(rt, "tls"),
		CLIConfigHome: path.Join(rt, "cli"),
		XDGStateHome:  path.Join(rt, "state"),
	}, nil
}

// GatewayConfigInput is what the private gateway's config is rendered
// from.
type GatewayConfigInput struct {
	// Name is the gateway's name (GatewayIdentity.Name).
	Name string
	// OCSFEndpoint is the OTLP/gRPC collector the gateway's supervisors
	// export OCSF events to. "" (the default) renders no export at all:
	// the export is off until this one field names an endpoint (lane O3
	// owns the receiver; the orchestrator connects the two). It must be
	// an http:// or https:// URL on a loopback address.
	OCSFEndpoint string
	// SandboxLabel is the Docker driver's sandbox namespace
	// (SandboxLabelFor): "" means Name; DefaultSandboxLabel renders no key,
	// which is the driver's own default.
	SandboxLabel string
	// Images are the runtime image references the Docker driver is given
	// (PinnedRuntimeImages: digest references, ledger row OSH-48). A zero
	// value renders no key (the driver's tag defaults), which is how a
	// config written before the pins is rendered for a comparison.
	Images RuntimeImages
}

// DefaultSandboxLabel is OpenShell v0.1.6's Docker driver default sandbox
// namespace (DockerComputeConfig.sandbox_label), which every gateway that
// does not set one shares.
const DefaultSandboxLabel = "default"

// SandboxLabelFor is the sandbox namespace the private gateway is rendered
// with (findings F-027 and OC2-A5). Its own name keeps its boxes apart
// from the package gateway's on the same engine. But while any run is
// recorded on it, the namespace it was started with is kept: the Docker
// driver finds and deletes boxes only in its current namespace, so a move
// would strand an abandoned run's box beyond the reaper's reach. A record
// with no label field was written before the field existed: either before
// the namespace was set (it ran in DefaultSandboxLabel) or by the first
// build that set it without recording it (it ran under its own name), so
// the label is inferred from the recorded config digest (finding
// OC2-V1): digestFor renders the config under a label and digests it as
// the record's was; the own name when that matches, else the default.
// With no record or no recorded run, the gateway's own name.
func SandboxLabelFor(name string, rec *GatewayRecord, recordedRuns int, digestFor func(label string) string) string {
	if rec == nil || recordedRuns <= 0 {
		return name
	}
	return RunningSandboxLabel(name, rec, digestFor)
}

// RunningSandboxLabel is the namespace the recorded gateway runs under:
// the label its record stores, else (a record with no label field) the
// gateway's own name when the recorded digest matches the render under it
// (digestFor, as SandboxLabelFor reads it), else the driver default; with
// no record, the gateway's own name. The drift read-back renders the
// current config under it, so a gateway in its own namespace reads clean
// (integration of lanes O4 and OC2).
func RunningSandboxLabel(name string, rec *GatewayRecord, digestFor func(label string) string) string {
	if rec == nil {
		return name
	}
	if rec.SandboxLabel != "" {
		return rec.SandboxLabel
	}
	if digestFor != nil && rec.ConfigDigest != "" && digestFor(name) == rec.ConfigDigest {
		return name
	}
	return DefaultSandboxLabel
}

// RenderGatewayConfig renders the private gateway's gateway.toml (schema
// version 2). It holds no secret: the key-encryption key is named by its
// variable, and the PKI is found through OPENSHELL_LOCAL_TLS_DIR. The
// bind-mount opt-in (decision D3) is set here, on Observer's own gateway
// only, which only Observer's runs use; resource admission is off, as in
// the measured runs (O1B-L1).
func RenderGatewayConfig(in GatewayConfigInput) (string, error) {
	if !gatewayNameRE.MatchString(in.Name) {
		return "", fmt.Errorf("sandboxopenshell.RenderGatewayConfig: gateway name %q is not a name", in.Name)
	}
	label := in.SandboxLabel
	if label == "" {
		label = in.Name
	}
	if !gatewayNameRE.MatchString(label) {
		return "", fmt.Errorf("sandboxopenshell.RenderGatewayConfig: sandbox label %q is not a name", label)
	}
	if in.OCSFEndpoint != "" && !LoopbackOTLP(in.OCSFEndpoint) {
		return "", fmt.Errorf("sandboxopenshell.RenderGatewayConfig: OCSF endpoint %q is not an http(s) URL on a loopback address", in.OCSFEndpoint)
	}
	var b strings.Builder
	b.WriteString("# Observer's private OpenShell gateway (gateway_mode \"managed\").\n")
	b.WriteString("# Written by Observer; edits are replaced at the next start.\n")
	b.WriteString("[openshell]\nversion = 2\n\n")
	b.WriteString("[openshell.gateway]\nname = " + strconv.Quote(in.Name) + "\ncompute_driver = \"docker\"\n\n")
	b.WriteString("[openshell.gateway.credential_storage]\nkey_encryption_key_env = " + strconv.Quote(GatewayKEKEnv) + "\n\n")
	b.WriteString("[openshell.drivers.docker]\nallow_driver_config = true\nenable_bind_mounts = true\n")
	// The private gateway's own sandbox namespace (finding F-027): the
	// Docker driver labels every container it creates
	// openshell.ai/sandbox-namespace=<sandbox_label> and scopes its list,
	// get, find and startup-reconcile paths to that one value (v0.1.6,
	// crates/openshell-driver-docker/src/lib.rs: managed_container_label_
	// filters, managed_resource_label_filters, find_managed_container_
	// summary). The default is "default", which the user's own package
	// gateway also uses on the same engine, so each took the other's boxes
	// for its own and stopped them ("Stopped Docker sandbox after control
	// supervisor failure"). The gateway's name is unique per install and
	// fits the label (the driver does not validate it; a path built from
	// it is sanitized). The driver default renders no key, so a gateway
	// kept in it (SandboxLabelFor) keeps the exact config it started with.
	if label != DefaultSandboxLabel {
		b.WriteString("sandbox_label = " + strconv.Quote(label) + "\n")
	}
	// The runtime images by digest (ledger row OSH-48, A12): the driver
	// takes a repo@sha256 reference as an exact, immutable image and never
	// refreshes it (v0.1.6 normalize_pull_reference and
	// supervisor_image_should_refresh), so a re-pushed tag cannot change
	// what Observer's boxes start from.
	for _, kv := range []struct{ key, ref string }{{"supervisor_image", in.Images.Supervisor}, {"sandbox_runtime_image", in.Images.Sandbox}} {
		if kv.ref == "" {
			continue
		}
		if !digestRef(kv.ref) {
			return "", fmt.Errorf("sandboxopenshell.RenderGatewayConfig: %s %q is not a digest reference", kv.key, kv.ref)
		}
		b.WriteString(kv.key + " = " + strconv.Quote(kv.ref) + "\n")
	}
	b.WriteString("\n[openshell.drivers.docker.resource_admission]\nenabled = false\n")
	if in.OCSFEndpoint != "" {
		b.WriteString("\n[openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = " + strconv.Quote(in.OCSFEndpoint) + "\n")
	}
	return b.String(), nil
}

// LoopbackOTLP reports whether raw is an http or https URL on a loopback
// address with a port and no path, credentials, query or fragment.
func LoopbackOTLP(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, " \t\n\"") {
		return false
	}
	if n, err := strconv.Atoi(u.Port()); err != nil || n < 1 || n > 65535 {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.Zone() == "" && ip.IsLoopback()
}

// GatewayConfigDigest is the digest the record keeps of what the private
// gateway was started with: its rendered config and the DOCKER_HOST the
// unit was given ("" for none; audit finding O2-V2), so a changed engine
// endpoint restarts it like a changed config (lifecycle rows G18 and G23
// compare it).
func GatewayConfigDigest(rendered, dockerHost string) string {
	sum := sha256.Sum256([]byte(rendered + "\x00DOCKER_HOST=" + dockerHost))
	return hex.EncodeToString(sum[:])[:16]
}

// GatewayVersionArgv is `openshell-gateway --version`.
func GatewayVersionArgv() []string { return []string{GatewayProgram, "--version"} }

// GatewayPreflightArgv is `openshell-gateway config preflight --path F`
// (validates the rendered config without starting anything).
func GatewayPreflightArgv(l GatewayLayout) []string {
	return []string{GatewayProgram, "config", "preflight", "--path", l.ConfigPath}
}

// GenerateCertsArgv is the PKI's first generation, into the runtime dir:
// the private gateway listens on 127.0.0.1 only, so its server certificate
// names that address (and generate-certs' own default SANs).
func GenerateCertsArgv(l GatewayLayout) []string {
	return []string{GatewayProgram, "generate-certs", "--output-dir", l.TLSDir, "--server-san", "127.0.0.1"}
}

// GatewayToolEnv is the environment of generate-certs, preflight and
// `gateway add` for the managed gateway: its private registry and state,
// and its TLS dir.
func GatewayToolEnv(l GatewayLayout) []string {
	return []string{
		"XDG_CONFIG_HOME=" + l.CLIConfigHome,
		"XDG_STATE_HOME=" + l.XDGStateHome,
		"OPENSHELL_LOCAL_TLS_DIR=" + l.TLSDir,
		"OPENSHELL_TELEMETRY_ENABLED=false",
	}
}

// GatewayAddArgv registers the private gateway in its private CLI
// registry (`openshell gateway add https://127.0.0.1:PORT --local --name
// N`; run with GatewayToolEnv, so the client bundle is imported from the
// restored PKI and nothing reaches the user's own registry).
func GatewayAddArgv(id GatewayIdentity, port int) ([]string, error) {
	if !gatewayNameRE.MatchString(id.Name) || port < 1 || port > 65535 {
		return nil, fmt.Errorf("sandboxopenshell.GatewayAddArgv: bad gateway name or port")
	}
	return []string{Program, "gateway", "add", ServerFor(port), "--local", "--name", id.Name}, nil
}

// unitPrefix starts every managed gateway unit name (IdentityFor).
const unitPrefix = "observer-openshell-gateway-"

// validUnit reports whether u is a managed gateway unit IdentityFor made.
func validUnit(u string) bool {
	rest, ok := strings.CutPrefix(u, unitPrefix)
	if !ok {
		return false
	}
	short, ok := strings.CutSuffix(rest, ".service")
	return ok && len(short) == 12 && installIDRE.MatchString(short)
}

// gatewayUnsetEnv are the gateway variables the unit unsets: a user
// manager passes its own environment to every unit (environment.d,
// `systemctl --user import-environment`), and each of these would change
// the private gateway's listener, authentication, storage or driver. The
// ones the unit sets itself, and the ones every start overrides with a
// flag, are not listed (a flag beats its variable).
var gatewayUnsetEnv = []string{
	"OPENSHELL_GATEWAY_CONFIG", "OPENSHELL_DISABLE_TLS", "OPENSHELL_TLS_CERT", "OPENSHELL_TLS_KEY",
	"OPENSHELL_TLS_CLIENT_CA", "OPENSHELL_OIDC_ISSUER", "OPENSHELL_OIDC_AUDIENCE", "OPENSHELL_ENABLE_MTLS_AUTH",
	"OPENSHELL_COMPUTE_DRIVER_SOCKET", "OPENSHELL_DRIVER_ADMISSION_CONFIG_JSON", "OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET",
	"OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP", "OPENSHELL_ENABLE_WEBSOCKET_TUNNEL", "OPENSHELL_SERVER_SAN",
	"OPENSHELL_GATEWAY_CREDENTIAL_KEY_ENCRYPTION_KEY", "OPENSHELL_GRPC_ENDPOINT", "XDG_DATA_HOME", "XDG_CACHE_HOME",
	"DOCKER_CONTEXT",
	// The runtime image variables (lane FU7, ledger row OSH-48): the
	// config's digest references win over them anyway; unset so no
	// imported value names an image even where the config names none.
	"OPENSHELL_SUPERVISOR_IMAGE", "OPENSHELL_SANDBOX_RUNTIME_IMAGE",
}

// GatewayStartInput is one start of the private gateway's unit.
type GatewayStartInput struct {
	ID     GatewayIdentity
	Layout GatewayLayout
	// GatewayBin is openshell-gateway's resolved absolute path.
	GatewayBin string
	Port       int
	// DockerHost is the daemon's DOCKER_HOST ("" for none): passed to the
	// unit explicitly, so the gateway drives the engine the probe's
	// canary ran against (audit finding O2-A8).
	DockerHost string
}

// GatewayEnvFile renders the unit's EnvironmentFile: the key-encryption
// key's variable and its base64 value, nothing else. A value outside the
// base64 alphabet is refused (the file's syntax must not depend on it).
func GatewayEnvFile(kek string) (string, error) {
	if kek == "" || strings.Trim(kek, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != "" {
		return "", fmt.Errorf("sandboxopenshell.GatewayEnvFile: the key-encryption key is not base64")
	}
	return GatewayKEKEnv + "=" + kek + "\n", nil
}

// validDockerHost reports whether a DOCKER_HOST value is one a systemd
// property can carry (no space, quote or control character).
func validDockerHost(h string) bool {
	return h != "" && !strings.ContainsAny(h, " \t\"'\\;$`") && strings.IndexFunc(h, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

// GatewayStartArgv is the transient user unit's start (`systemd-run
// --user`), the way the package's user service runs the gateway (O0-L2
// receipt 8a047f) with every path pointed at Observer's own dirs:
// telemetry forced off (risk RK-11) and its endpoint blanked, loopback
// only, no health or metrics port, operator authentication off, the
// database under the row's state dir, the PKI from the private runtime
// dir. The key-encryption key reaches the gateway through an owner-only
// EnvironmentFile in the RAM dir (GatewayEnvFile, written by the driver
// before the start and removed at the stop), so it never appears on a
// command line, in the transient unit file or in `systemctl --user show`
// (EnvironmentFile names only the path). The name-only --setenv form is
// not used: systemd 245 refuses it (audit finding O2-A6).
func GatewayStartArgv(in GatewayStartInput) ([]string, error) {
	switch {
	case !validUnit(in.ID.Unit):
		return nil, fmt.Errorf("sandboxopenshell.GatewayStartArgv: unit %q is not a managed gateway unit", in.ID.Unit)
	case !gatewayNameRE.MatchString(in.ID.Name):
		return nil, fmt.Errorf("sandboxopenshell.GatewayStartArgv: gateway name %q is not a name", in.ID.Name)
	case !safePath(in.GatewayBin):
		return nil, fmt.Errorf("sandboxopenshell.GatewayStartArgv: gateway binary %q is not an absolute, clean path", in.GatewayBin)
	case in.Port < 1 || in.Port > 65535:
		return nil, fmt.Errorf("sandboxopenshell.GatewayStartArgv: port %d", in.Port)
	}
	l := in.Layout
	if in.DockerHost != "" && !validDockerHost(in.DockerHost) {
		return nil, fmt.Errorf("sandboxopenshell.GatewayStartArgv: DOCKER_HOST %q cannot be passed to the unit", in.DockerHost)
	}
	for _, p := range []string{l.ConfigPath, l.DBPath, l.TLSDir, l.CLIConfigHome, l.XDGStateHome, l.EnvFile} {
		if !safePath(p) {
			return nil, fmt.Errorf("sandboxopenshell.GatewayStartArgv: path %q is not an absolute, clean path", p)
		}
	}
	argv := []string{
		// No --collect: a unit that fails (its start limit included) stays
		// loaded as "failed" until the next start's reset-failed, so the
		// lifecycle table can read the outcome (audit finding O2-V6).
		"systemd-run", "--user", "--unit", in.ID.Unit, "--quiet",
		"--description=Observer private OpenShell gateway",
		"--property=Type=simple", "--property=UMask=0077",
		"--property=Restart=on-failure", "--property=RestartSec=5s",
		// A unit that keeps failing lands in failed after five starts in
		// two minutes instead of reading "activating" forever (audit
		// finding O2-A10).
		"--property=StartLimitIntervalSec=120", "--property=StartLimitBurst=5",
		"--property=UnsetEnvironment=" + strings.Join(gatewayUnsetEnv, " "),
		// The key-encryption key: an owner-only file in the RAM dir the
		// user manager reads at each start, so the value is in no argv,
		// no transient unit file and no `systemctl --user show` answer.
		"--property=EnvironmentFile=" + l.EnvFile,
		"--setenv=OPENSHELL_TELEMETRY_ENABLED=false",
		"--setenv=OPENSHELL_TELEMETRY_ENDPOINT=",
		"--setenv=OPENSHELL_LOCAL_TLS_DIR=" + l.TLSDir,
		"--setenv=XDG_CONFIG_HOME=" + l.CLIConfigHome,
		"--setenv=XDG_STATE_HOME=" + l.XDGStateHome,
	}
	if in.DockerHost != "" {
		argv = append(argv, "--setenv=DOCKER_HOST="+in.DockerHost)
	}
	argv = append(argv, "--", in.GatewayBin,
		"--config", l.ConfigPath,
		"--db-url", "sqlite:"+l.DBPath,
		"--name", in.ID.Name,
		"--bind-address", "127.0.0.1",
		"--port", strconv.Itoa(in.Port),
		"--health-port", "0",
		"--metrics-port", "0",
		"--compute-driver", "docker",
		"--enable-operator-auth", "false",
	)
	return argv, nil
}

// UnitArgv is `systemctl --user VERB UNIT` for is-active, stop and
// reset-failed.
func UnitArgv(verb, unit string) ([]string, error) {
	switch verb {
	case "is-active", "stop", "reset-failed":
	default:
		return nil, fmt.Errorf("sandboxopenshell.UnitArgv: verb %q", verb)
	}
	if !validUnit(unit) {
		return nil, fmt.Errorf("sandboxopenshell.UnitArgv: unit %q is not a managed gateway unit", unit)
	}
	return []string{"systemctl", "--user", verb, unit}, nil
}

// UnitShowArgv reads a unit's start command (`systemctl --user show -p
// ExecStart --value UNIT`): UnitConfigPath reads which config it runs.
func UnitShowArgv(unit string) ([]string, error) {
	if !validUnit(unit) {
		return nil, fmt.Errorf("sandboxopenshell.UnitShowArgv: unit %q is not a managed gateway unit", unit)
	}
	return []string{"systemctl", "--user", "show", "-p", "ExecStart", "--value", unit}, nil
}

// UnitConfigPath reads the --config path of the gateway a unit runs from
// UnitShowArgv's answer ("{ path=... ; argv[]=BIN --config PATH ... ;
// ... }"); ok is false when the answer names no start command (the unit
// is not loaded) or no --config. Every path GatewayStartArgv puts on the
// argv is a safePath, so a space never sits inside one (ledger row
// OSH-42: before a stop or restart, the unit's config must be this
// layout's; a unit of the same name run from another state dir, a copy
// of this one, is never stopped).
func UnitConfigPath(out string) (string, bool) {
	_, rest, found := strings.Cut(out, "argv[]=")
	if !found {
		return "", false
	}
	if i := strings.Index(rest, " ;"); i >= 0 {
		rest = rest[:i]
	}
	f := strings.Fields(rest)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "--config" {
			return f[i+1], true
		}
	}
	return "", false
}

// SupervisorArgv asks the user manager whether it runs (`systemctl --user
// is-system-running`): ParseSupervisor reads it.
func SupervisorArgv() []string { return []string{"systemctl", "--user", "is-system-running"} }

// ParseSupervisor reads is-system-running's answer: a manager that runs
// (even degraded, or still starting) can start a transient unit.
func ParseSupervisor(out string) bool {
	switch firstLine(strings.TrimSpace(out)) {
	case "running", "degraded", "starting", "initializing":
		return true
	}
	return false
}
