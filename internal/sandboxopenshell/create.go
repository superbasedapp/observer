package sandboxopenshell

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Program is the OpenShell CLI's name. The driver resolves it to an
// absolute path (internal/extrun/host, shims excluded) and replaces argv[0].
const Program = "openshell"

// Target is the gateway a command talks to: Gateway is a registered
// gateway name (-g, "" for the CLI's active gateway) and Endpoint an
// explicit endpoint (--gateway-endpoint, "" for none).
//
// Only StatusArgv takes an empty Target (the probe's question "which gateway
// is active?"). Every command about a box (create, list, get, delete) needs
// the gateway pinned (audit finding O1A-A9): the CLI's active gateway is the
// user's to switch between a create and a reap, and the other gateway then
// answers the exact not-found text for a box that is still running on the
// first, so the reaper would read it gone and leak it. The driver records
// the gateway the create-time status answer named (StatusAnswer.Gateway)
// and passes it on every later call.
type Target struct {
	Gateway  string
	Endpoint string
	// ConfigHome is the XDG_CONFIG_HOME the CLI runs with for this target
	// ("" for the user's own): the managed gateway's private registry
	// (GatewayLayout.CLIConfigHome), so a command about Observer's own
	// gateway never reads or writes the user's ~/.config/openshell, and a
	// command about the user's gateway never sees Observer's. It is an
	// environment value, never a flag (TargetEnv).
	ConfigHome string `json:",omitempty"`
}

// TargetEnv is the environment a command about t runs with: XDG_CONFIG_HOME
// set to t's private registry, or nothing (the user's own). ok is false for
// a ConfigHome that is not an absolute, clean path a variable can carry.
func TargetEnv(t Target) (env []string, ok bool) {
	if t.ConfigHome == "" {
		return nil, true
	}
	if !safePath(t.ConfigHome) {
		return nil, false
	}
	return []string{"XDG_CONFIG_HOME=" + t.ConfigHome}, true
}

// ErrUnpinnedTarget refuses a box command whose Target names no gateway.
var ErrUnpinnedTarget = errors.New("sandboxopenshell: a box command needs the gateway pinned (a name or an endpoint), never the CLI's active gateway")

// Pinned reports whether t names a gateway (a name, an endpoint, or both).
func (t Target) Pinned() bool { return t.Gateway != "" || t.Endpoint != "" }

// pinnedGlobals renders the target's global flags, refusing an empty one.
func (t Target) pinnedGlobals() ([]string, error) {
	if !t.Pinned() {
		return nil, ErrUnpinnedTarget
	}
	return t.globals()
}

// gatewayNameRE is the shape of a gateway name.
var gatewayNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// globals renders the target's global flags, after the program name.
func (t Target) globals() ([]string, error) {
	var out []string
	if _, ok := TargetEnv(t); !ok {
		return nil, fmt.Errorf("sandboxopenshell: the target's CLI config home %q is not an absolute, clean path", t.ConfigHome)
	}
	if t.Gateway != "" {
		if !gatewayNameRE.MatchString(t.Gateway) {
			return nil, fmt.Errorf("sandboxopenshell: gateway name %q is not a name", t.Gateway)
		}
		out = append(out, "-g", t.Gateway)
	}
	if t.Endpoint != "" {
		if !strings.HasPrefix(t.Endpoint, "https://") || strings.ContainsAny(t.Endpoint, " \t\n") {
			return nil, fmt.Errorf("sandboxopenshell: gateway endpoint %q is not an https URL", t.Endpoint)
		}
		out = append(out, "--gateway-endpoint", t.Endpoint)
	}
	return out, nil
}

// nameRE is the shape of a sandbox name: a DNS-1123 label of at most 19
// bytes (OpenShell's MAX_ROUTABLE_NAME_LEN, doc 01 CO-1).
var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,17}[a-z0-9])?$`)

// namePrefix starts every sandbox name Observer creates.
const namePrefix = "sbo-"

// ValidSandboxName reports whether n has the shape of a sandbox name (the
// reaper reads only such lines of a list answer).
func ValidSandboxName(n string) bool { return nameRE.MatchString(n) }

// SandboxName is the sandbox name of a run: "sbo-" and the first 15
// characters of the lowercase unpadded base32 of sha256(runID), 19 bytes in
// all. Lookup and the reaper never parse it; they select on the labels.
func SandboxName(runID string) string {
	sum := sha256.Sum256([]byte(runID))
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
	return namePrefix + enc[:15]
}

// CreateInput is one run's `openshell sandbox create`.
type CreateInput struct {
	Target Target
	// Name is SandboxName(run id).
	Name string
	// PolicyPath is the absolute path of the run's policy file (0600, the
	// driver writes Plan.PolicyYAML there).
	PolicyPath string
	// DriverConfigJSON is Plan.DriverConfigJSON.
	DriverConfigJSON string
	// Labels are RunLabels(install id, run id).
	Labels []Label
	// Image is the sandbox image (--from; "" for the gateway's default).
	Image string
	// Env is Plan.Env.
	Env []string
	// Command is the box's main process (after "--", exact argv, no shell).
	Command []string
}

// CreateArgv returns the fixed argv of `openshell sandbox create` for one
// run, the program name first. The flags are the ones lane O0's harness ran
// live at v0.1.6: --no-auto-providers (no OpenShell provider credential),
// --no-keep (the box is deleted when its command exits; a killed client
// leaves it, which the labelled reaper handles) and --tty (the CLI forwards
// the terminal size, O0 R5).
func CreateArgv(in CreateInput) ([]string, error) {
	g, err := in.Target.pinnedGlobals()
	if err != nil {
		return nil, err
	}
	if !nameRE.MatchString(in.Name) {
		return nil, fmt.Errorf("sandboxopenshell.CreateArgv: sandbox name %q is not a DNS label of at most 19 bytes", in.Name)
	}
	if !cleanAbs(in.PolicyPath) {
		return nil, fmt.Errorf("sandboxopenshell.CreateArgv: policy path %q is not absolute and clean", in.PolicyPath)
	}
	if !json.Valid([]byte(in.DriverConfigJSON)) || !strings.HasPrefix(in.DriverConfigJSON, "{") {
		return nil, fmt.Errorf("sandboxopenshell.CreateArgv: driver config is not a JSON object")
	}
	if err := checkRunLabels(in.Labels); err != nil {
		return nil, fmt.Errorf("sandboxopenshell.CreateArgv: %w", err)
	}
	if in.Image != "" && (strings.HasPrefix(in.Image, "-") || strings.ContainsAny(in.Image, " \t\n")) {
		return nil, fmt.Errorf("sandboxopenshell.CreateArgv: image %q is not an image reference", in.Image)
	}
	if len(in.Command) == 0 || in.Command[0] == "" {
		return nil, fmt.Errorf("sandboxopenshell.CreateArgv: no command")
	}
	argv := append([]string{Program}, g...)
	argv = append(argv, "sandbox", "create", "--name", in.Name, "--policy", in.PolicyPath,
		"--driver-config-json", in.DriverConfigJSON)
	for _, l := range in.Labels {
		argv = append(argv, "--label", l.String())
	}
	argv = append(argv, "--no-auto-providers", "--no-keep", "--tty")
	if in.Image != "" {
		argv = append(argv, "--from", in.Image)
	}
	for _, kv := range in.Env {
		k, _, found := strings.Cut(kv, "=")
		if !found || !envKeyRE.MatchString(k) || strings.ContainsAny(kv, "\x00\n") {
			return nil, fmt.Errorf("sandboxopenshell.CreateArgv: %w: %q", ErrEnv, k)
		}
		argv = append(argv, "--env", kv)
	}
	argv = append(argv, "--")
	return append(argv, in.Command...), nil
}

// checkRunLabels requires both run labels, each passing the grammar.
func checkRunLabels(labels []Label) error {
	have := map[string]bool{}
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return err
		}
		if have[l.Key] {
			return fmt.Errorf("label key %q twice", l.Key)
		}
		have[l.Key] = true
	}
	for _, k := range []string{LabelInstall, LabelRun} {
		if !have[k] {
			return fmt.Errorf("the run labels lack %s (the reaper selects on it)", k)
		}
	}
	return nil
}

// ListArgv returns `openshell sandbox list --selector <sel> --names`, the
// reaper's list of the boxes carrying labels.
func ListArgv(t Target, labels []Label) ([]string, error) {
	g, err := t.pinnedGlobals()
	if err != nil {
		return nil, err
	}
	sel, err := Selector(labels)
	if err != nil {
		return nil, err
	}
	argv := append([]string{Program}, g...)
	return append(argv, "sandbox", "list", "--selector", sel, "--names"), nil
}

// GetArgv returns `openshell sandbox get <name> -o json` (ClassifyGet reads
// its answer).
func GetArgv(t Target, name string) ([]string, error) {
	g, err := t.pinnedGlobals()
	if err != nil {
		return nil, err
	}
	if !nameRE.MatchString(name) {
		return nil, fmt.Errorf("sandboxopenshell.GetArgv: sandbox name %q is not a name", name)
	}
	argv := append([]string{Program}, g...)
	return append(argv, "sandbox", "get", name, "-o", "json"), nil
}

// DeleteArgv returns `openshell sandbox delete <name>...`. It never renders
// --all.
func DeleteArgv(t Target, names ...string) ([]string, error) {
	g, err := t.pinnedGlobals()
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("sandboxopenshell.DeleteArgv: no sandbox name")
	}
	argv := append([]string{Program}, g...)
	argv = append(argv, "sandbox", "delete")
	for _, n := range names {
		if !nameRE.MatchString(n) {
			return nil, fmt.Errorf("sandboxopenshell.DeleteArgv: sandbox name %q is not a name", n)
		}
		argv = append(argv, n)
	}
	return argv, nil
}

// StatusArgv returns `openshell status -o json` (the probe's gateway status,
// authentication and version, and the gateway name the driver pins every
// later box command to). An empty Target asks the CLI's active gateway.
func StatusArgv(t Target) ([]string, error) {
	g, err := t.globals()
	if err != nil {
		return nil, err
	}
	argv := append([]string{Program}, g...)
	return append(argv, "status", "-o", "json"), nil
}
