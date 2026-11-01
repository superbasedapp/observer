package sandboxoci

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/devcontainer"
)

// devcontainer.go reads a repository's .devcontainer/devcontainer.json for
// the oci-runc driver (SBX-BE-3; sandbox plan v2 section 13 P3). Adoption
// is an explicit per-repository consent, never automatic, and the reader
// takes exactly two things from the file: `image`, by digest only, and the
// `containerEnv` entries whose names pass the allow-list, where an
// Observer-owned variable (base URLs, proxy variables, config dirs, markers,
// loader and runtime hooks) can never be set or overridden. Every
// host-executing or privilege-raising field is ignored and named back, so
// the consent text can say so. A repository Dockerfile (`build`) is never
// built.

// maxDevcontainer caps the file the reader accepts (the shared reader's
// cap).
const maxDevcontainer = devcontainer.MaxBytes

// The fields that would run something on the host or raise the container's
// privilege are internal/devcontainer's table (devcontainer.IgnoredFields):
// each is ignored, never honoured, and the repository trust check reports
// them from the same reader.

// envNameRE is the shape of an allowed variable name.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// envDeniedPrefixes and envDeniedNames are the variables a repository may
// never set: Observer's own, the proxy and base-URL routing, the config
// dirs the inner launcher and the tools read, credentials, and loader or
// runtime hooks.
var (
	envDeniedPrefixes = []string{"OBSERVER_", "SBO_", "ANTHROPIC_", "OPENAI_", "CLAUDE_", "CODEX_", "GEMINI_", "GOOGLE_", "AWS_", "AZURE_", "GIT_", "SSH_", "DOCKER_", "CONTAINER_", "LD_", "DYLD_", "NODE_", "NPM_", "PYTHON", "XDG_"}
	envDeniedSuffixes = []string{"_BASE_URL", "_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CONFIG_DIR", "_HOME", "_PROXY"}
	envDeniedNames    = []string{"PATH", "HOME", "USER", "SHELL", "TERM", "HOSTNAME", "PWD", "TMPDIR", "SANDBOX", "QWEN_SANDBOX", "CURSOR_SANDBOX", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy", "BASH_ENV", "ENV", "PROMPT_COMMAND", "PERL5OPT", "RUBYOPT", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"}
)

// The image ENV rule (SBX-P3A merge finding F2). Docker and Podman merge an
// image's own Config.Env UNDER the create body's environment, so a name the
// box's allow-listed environment does not set keeps the IMAGE's value: a
// consented .devcontainer image (or the configured one) setting a base URL or
// a proxy would send the agent's traffic, and its key, wherever it names. The
// driver therefore reads the image's Config.Env before it creates anything
// and refuses an image that names one of these (compared in upper case);
// every other image variable (PATH, LANG, the toolchain's own) is the
// image's to set and is kept. The choice is to refuse, never to blank: an
// empty value is still a value a tool may read differently from an unset one.
var (
	imageEnvDeniedNames = []string{
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
		"BASH_ENV", "ENV", "PROMPT_COMMAND", "PERL5OPT", "RUBYOPT", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
		"DOCKER_HOST", "CONTAINER_HOST",
	}
	imageEnvDeniedPrefixes = []string{"GIT_", "LD_", "DYLD_", "OBSERVER_", "SBO_", "ANTHROPIC_", "OPENAI_", "CLAUDE_", "CODEX_", "GEMINI_"}
	imageEnvDeniedSuffixes = []string{"_BASE_URL", "_PROXY"}
)

// imageEnvForbidden reports whether an image may not set name.
func imageEnvForbidden(name string) bool {
	up := strings.ToUpper(strings.TrimSpace(name))
	for _, n := range imageEnvDeniedNames {
		if up == n {
			return true
		}
	}
	for _, p := range imageEnvDeniedPrefixes {
		if strings.HasPrefix(up, p) {
			return true
		}
	}
	for _, s := range imageEnvDeniedSuffixes {
		if strings.HasSuffix(up, s) {
			return true
		}
	}
	return false
}

// ImageEnvRefusal judges an image's own Config.Env: built_below_plan naming
// every forbidden variable (sorted) when the image sets any, pass otherwise.
// The run is refused before the container is created.
func ImageEnvRefusal(env []string) Verdict {
	var bad []string
	seen := map[string]bool{}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if k != "" && imageEnvForbidden(k) && !seen[k] {
			seen[k] = true
			bad = append(bad, k)
		}
	}
	if len(bad) == 0 {
		return pass()
	}
	sort.Strings(bad)
	return refuse(VerdictBuiltBelowPlan, "the image's own environment sets "+strings.Join(bad, ", ")+
		", which the engine would pass into the box where Observer's environment does not set it (routing, proxy and loader variables are Observer's to set); use an image that does not set them")
}

// AllowedContainerEnv reports whether a repository may set name.
func AllowedContainerEnv(name string) bool {
	if !envNameRE.MatchString(name) {
		return false
	}
	up := strings.ToUpper(name)
	for _, n := range envDeniedNames {
		if name == n || up == strings.ToUpper(n) {
			return false
		}
	}
	for _, p := range envDeniedPrefixes {
		if strings.HasPrefix(up, p) {
			return false
		}
	}
	for _, s := range envDeniedSuffixes {
		if strings.HasSuffix(up, s) {
			return false
		}
	}
	return true
}

// Devcontainer is what the reader takes from the file.
type Devcontainer struct {
	// Image is the image, pinned by digest; empty when the file has none or
	// it is a tag.
	Image string
	// ImageRefused says why a present image is not used.
	ImageRefused string
	// Env are the allowed containerEnv entries, KEY=value, sorted.
	Env []string
	// DroppedEnv are the containerEnv names the allow-list refused, sorted.
	DroppedEnv []string
	// Ignored are the host-executing or privilege fields present, sorted.
	Ignored []string
	// IgnoredRaw holds each ignored field's value as compact JSON, for the
	// repository trust check's N2 rows (the exact content a developer can
	// accept); never honoured.
	IgnoredRaw map[string]string
}

// ParseDevcontainer reads devcontainer.json (JSON with comments and
// trailing commas) through the one shared reader (internal/devcontainer)
// and adopts from it: the image by digest only and the allow-listed
// containerEnv entries.
func ParseDevcontainer(raw []byte) (Devcontainer, error) {
	f, err := devcontainer.ParseDevcontainer(raw)
	if err != nil {
		return Devcontainer{}, fmt.Errorf("sandboxoci: %w", err)
	}
	d := Devcontainer{Ignored: f.Ignored, IgnoredRaw: f.IgnoredRaw}
	if f.Image != nil {
		var s string
		if json.Unmarshal(f.Image, &s) != nil {
			d.ImageRefused = "image is not a string"
		} else if err := ValidateImageRef(s); err != nil {
			d.ImageRefused = err.Error()
		} else {
			d.Image = strings.TrimSpace(s)
		}
	}
	for k, v := range f.ContainerEnv {
		if AllowedContainerEnv(k) && !strings.ContainsAny(v, "\x00\n\r") {
			d.Env = append(d.Env, k+"="+v)
		} else {
			d.DroppedEnv = append(d.DroppedEnv, k)
		}
	}
	sort.Strings(d.Env)
	sort.Strings(d.DroppedEnv)
	return d, nil
}

// StripJSONC removes // and /* */ comments outside strings and trailing
// commas before a closing brace or bracket, leaving plain JSON (the shared
// reader's).
func StripJSONC(in []byte) []byte { return devcontainer.StripJSONC(in) }
