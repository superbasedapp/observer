package extrun

import (
	"fmt"
	"sort"
	"strings"
)

// envApplies says which side of an EnvSpec an envRule covers.
type envApplies int

const (
	// appliesInherit: the rule refuses the name only when it would be
	// copied from the daemon's environment.
	appliesInherit envApplies = iota + 1
	// appliesBoth: the rule refuses the name on either side.
	appliesBoth
)

// envRule is one row of the refused-name table. A name matches when it
// equals Exact, starts with Prefix or ends with Suffix (compared upper-case,
// so the table holds on Windows, where names are case-insensitive, and on
// Unix, where a lower-case spelling would otherwise slip past).
type envRule struct {
	exact   string
	prefix  string
	suffix  string
	applies envApplies
	reason  string
}

// envRules is the refused-name table, walked top-down; the first match wins.
// Loader-injection names and PATH are refused on both sides (PATH comes only
// from EnvSpec.PathDirs). Secret-shaped names are refused for inheritance
// only: a caller that deliberately hands a credential to a program passes it
// as a literal in EnvSpec.Set.
var envRules = []envRule{
	{exact: "PATH", applies: appliesBoth, reason: "PATH comes only from PathDirs"},
	{prefix: "LD_", applies: appliesBoth, reason: "dynamic loader injection"},
	{prefix: "DYLD_", applies: appliesBoth, reason: "dynamic loader injection"},
	{prefix: "ANTHROPIC_", applies: appliesInherit, reason: "AI provider credentials"},
	{prefix: "OPENAI_", applies: appliesInherit, reason: "AI provider credentials"},
	{prefix: "AZURE_OPENAI_", applies: appliesInherit, reason: "AI provider credentials"},
	{prefix: "GEMINI_", applies: appliesInherit, reason: "AI provider credentials"},
	{prefix: "GOOGLE_", applies: appliesInherit, reason: "cloud credentials"},
	{prefix: "AWS_", applies: appliesInherit, reason: "cloud credentials"},
	{prefix: "AZURE_", applies: appliesInherit, reason: "cloud credentials"},
	{prefix: "GH_", applies: appliesInherit, reason: "forge credentials"},
	{prefix: "GITHUB_", applies: appliesInherit, reason: "forge credentials"},
	{prefix: "OBSERVER_", applies: appliesInherit, reason: "the daemon's own settings and tokens"},
	{prefix: "SBO_", applies: appliesInherit, reason: "the daemon's own settings and tokens"},
	{prefix: "SBCI_", applies: appliesInherit, reason: "the daemon's own settings and tokens"},
	{exact: "HTTP_PROXY", applies: appliesInherit, reason: "proxy settings can carry credentials"},
	{exact: "HTTPS_PROXY", applies: appliesInherit, reason: "proxy settings can carry credentials"},
	{exact: "ALL_PROXY", applies: appliesInherit, reason: "proxy settings can carry credentials"},
	{exact: "FTP_PROXY", applies: appliesInherit, reason: "proxy settings can carry credentials"},
	{exact: "SSH_AUTH_SOCK", applies: appliesInherit, reason: "SSH agent access"},
	{exact: "GPG_AGENT_INFO", applies: appliesInherit, reason: "GPG agent access"},
	{suffix: "_KEY", applies: appliesInherit, reason: "credential-shaped name"},
	{suffix: "_TOKEN", applies: appliesInherit, reason: "credential-shaped name"},
	{suffix: "_SECRET", applies: appliesInherit, reason: "credential-shaped name"},
	{suffix: "_PASSWORD", applies: appliesInherit, reason: "credential-shaped name"},
	{suffix: "_PASSWD", applies: appliesInherit, reason: "credential-shaped name"},
	{suffix: "_CREDENTIALS", applies: appliesInherit, reason: "credential-shaped name"},
	{suffix: "_CREDENTIAL", applies: appliesInherit, reason: "credential-shaped name"},
	{suffix: "APIKEY", applies: appliesInherit, reason: "credential-shaped name"},
	// Connection URLs and DSNs that commonly embed a password
	// (postgres://user:pass@host, redis://:pass@host).
	{suffix: "DATABASE_URL", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "DB_URL", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "POSTGRES_URL", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "REDIS_URL", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "MONGO_URL", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "MONGO_URI", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "MONGODB_URI", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "AMQP_URL", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "BROKER_URL", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
	{suffix: "_DSN", applies: appliesInherit, reason: "connection URL, commonly carries a password"},
}

// refusedName returns the reason name is refused on the given side, or "".
func refusedName(name string, inherit bool) string {
	up := strings.ToUpper(name)
	for _, r := range envRules {
		if r.applies == appliesInherit && !inherit {
			continue
		}
		if (r.exact != "" && up == r.exact) ||
			(r.prefix != "" && strings.HasPrefix(up, r.prefix)) ||
			(r.suffix != "" && strings.HasSuffix(up, r.suffix)) {
			return r.reason
		}
	}
	return ""
}

// validEnvName reports whether name can be a variable name: non-empty, with
// no "=" and no NUL.
func validEnvName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "=\x00")
}

// BuildEnv turns spec into the exact environment the program sees, sorted
// by name. getenv reads one variable of the daemon's environment (ok false
// when unset); it is consulted only for the names in spec.Inherit. An
// inherited name that is unset is skipped. Any refused or malformed entry,
// a duplicate name (case-insensitive on Windows) or a relative PATH entry
// fails the whole build: a partial environment is never used.
func BuildEnv(spec EnvSpec, goos string, getenv func(string) (string, bool)) ([]string, error) {
	seen := map[string]bool{}
	key := func(name string) string {
		if goos == "windows" {
			return strings.ToUpper(name)
		}
		return name
	}
	var out []string
	add := func(name, value string) error {
		k := key(name)
		if seen[k] {
			return fmt.Errorf("extrun.BuildEnv: %s is named twice", name)
		}
		seen[k] = true
		if strings.ContainsRune(value, 0) {
			return fmt.Errorf("extrun.BuildEnv: the value of %s holds a NUL byte", name)
		}
		out = append(out, name+"="+value)
		return nil
	}
	for _, kv := range spec.Set {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !validEnvName(name) {
			return nil, fmt.Errorf("extrun.BuildEnv: %q is not NAME=VALUE", kv)
		}
		if why := refusedName(name, false); why != "" {
			return nil, fmt.Errorf("extrun.BuildEnv: %s is refused (%s)", name, why)
		}
		if err := add(name, value); err != nil {
			return nil, err
		}
	}
	for _, name := range spec.Inherit {
		if !validEnvName(name) {
			return nil, fmt.Errorf("extrun.BuildEnv: %q is not a variable name", name)
		}
		if why := refusedName(name, true); why != "" {
			return nil, fmt.Errorf("extrun.BuildEnv: %s may not be inherited (%s)", name, why)
		}
		if getenv == nil {
			continue
		}
		value, ok := getenv(name)
		if !ok {
			continue
		}
		if err := add(name, value); err != nil {
			return nil, err
		}
	}
	if len(spec.PathDirs) > 0 {
		sep := ":"
		if goos == "windows" {
			sep = ";"
		}
		for _, d := range spec.PathDirs {
			if !IsAbs(goos, d) || strings.Contains(d, sep) {
				return nil, fmt.Errorf("extrun.BuildEnv: PATH entry %q is not one absolute directory", d)
			}
		}
		if err := add("PATH", strings.Join(spec.PathDirs, sep)); err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// EnvNames returns the variable names of env, in order.
func EnvNames(env []string) []string {
	names := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		names = append(names, name)
	}
	return names
}

// WindowsEssentials are the variables most Windows programs need to start at
// all. A caller running on Windows names them in EnvSpec.Inherit; the runner
// never adds them on its own. (Go's os/exec on Windows itself adds
// SYSTEMROOT when it is missing; that one addition is outside this list's
// control and is recorded in the ledger row SHR-1.)
var WindowsEssentials = []string{"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP"}

// IsAbs reports whether p is absolute for goos, without touching the
// filesystem: a leading slash on Unix; a drive letter followed by a
// separator, or a UNC prefix, on Windows.
func IsAbs(goos, p string) bool {
	if goos != "windows" {
		return strings.HasPrefix(p, "/")
	}
	if strings.HasPrefix(p, `\\`) {
		return len(p) > 2
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0]
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return false
}
