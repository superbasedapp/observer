package seccustom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// SchemaV1 is the only manifest schema this build reads.
const SchemaV1 = "sbo.custom-scanner.v1"

// Manifest is one user-configured scanner driver (section 8.6). Every field
// is either a literal shown read-only in the confirm dialog or a value from
// a closed set chosen with a picker.
type Manifest struct {
	Schema  string `json:"schema"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Template is the built-in template the manifest came from, "" for a
	// manifest file of the user's own.
	Template string `json:"template,omitempty"`
	// Executable is an absolute path, picked at import from the
	// executables Observer discovered, never typed.
	Executable string `json:"executable"`
	// ExecutableSHA256 is the pinned digest, computed at import and
	// confirmed; empty in a file means "compute it".
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
	// Argv is literal strings plus at most one each of the whole-token
	// placeholders {targets_file}, {output_file} and {project_root}.
	Argv   []string `json:"argv"`
	Input  Input    `json:"input"`
	Output Output   `json:"output"`
	Limits Limits   `json:"limits"`
	// Companions are the executables the program itself runs (gosec runs
	// go), each digest-pinned; their directories are the only PATH the
	// program gets.
	Companions []Companion `json:"companions,omitempty"`
	// Env is a list of entries from the closed environment table
	// (EnvChoices), never a free NAME=VALUE.
	Env []string `json:"env,omitempty"`
	// Cache is "none" or "per_driver" (an Observer-owned directory).
	Cache Cache `json:"cache"`
	// SelfTest is the planted fixture run at import and whenever a digest
	// or version changes; without one a run is never clean.
	SelfTest *SelfTest `json:"self_test,omitempty"`
	// UnknownStderr are literal stderr substrings that mark a run unknown
	// (gosec's "skipping SSA analysis").
	UnknownStderr []string `json:"unknown_stderr,omitempty"`
	// ExitCodes say what each exit status means; an unnamed status is a
	// failure.
	ExitCodes []ExitCode  `json:"exit_codes"`
	Network   Network     `json:"network"`
	Category  string      `json:"category"`
	Severity  SeverityMap `json:"severity_map"`
	// Confidence is how each finding's confidence is chosen.
	Confidence ConfidenceMap `json:"confidence_map"`
	// BlockingRules may be set only in an org-approved manifest.
	BlockingRules []string `json:"blocking_rules,omitempty"`
}

// Input is how the targets reach the program.
type Input string

// The Input values.
const (
	InputTargetsFile Input = "targets_file"
	InputStdin       Input = "stdin"
)

// Output is where the program writes its SARIF.
type Output string

// The Output values.
const (
	OutputSARIFFile   Output = "sarif_file"
	OutputSARIFStdout Output = "sarif_stdout"
)

// Cache is the cache directory choice.
type Cache string

// The Cache values.
const (
	CacheNone      Cache = "none"
	CachePerDriver Cache = "per_driver"
)

// Companion is one companion executable.
type Companion struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	// OnPath puts its directory on the program's PATH.
	OnPath bool `json:"on_path,omitempty"`
	// VersionArgv asks it its version before every run (recorded on the
	// run: gosec built with Go 1.26 drops three rules against Go 1.27).
	VersionArgv []string `json:"version_argv,omitempty"`
	// VersionFormat names how the version is read from that answer, from
	// the closed table VersionFormats ("" is a plain dotted version).
	VersionFormat string `json:"version_format,omitempty"`
}

// versionFormats is the closed table of version answer shapes: the regular
// expressions are Observer's, never the manifest's.
var versionFormats = map[string]*regexp.Regexp{
	// "go version go1.27.2 linux/amd64"
	GoToolchainFormat: regexp.MustCompile(`\bgo(\d+\.\d+(?:\.\d+)?)\b`),
}

// VersionFormats returns the closed version format names.
func VersionFormats() []string {
	out := make([]string, 0, len(versionFormats))
	for k := range versionFormats {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SelfTest names a built-in fixture and the rules it must report.
type SelfTest struct {
	Fixture     string   `json:"fixture"`
	ExpectRules []string `json:"expect_rules"`
}

// ExitCode is one row of the exit-code table.
type ExitCode struct {
	Code    int                `json:"code"`
	Meaning extrun.ExitMeaning `json:"meaning"`
}

// Network is none or a declared host list.
type Network struct {
	Mode  string   `json:"mode"`
	Hosts []string `json:"hosts,omitempty"`
}

// The Network modes.
const (
	NetworkNone  = "none"
	NetworkHosts = "hosts"
)

// SeveritySource is where a result's severity is read (revision 2.4
// [JSP-12]: each template names its source explicitly).
type SeveritySource string

// The SeveritySource values.
const (
	// SeverityLevel reads the result's SARIF level (default "warning").
	SeverityLevel SeveritySource = "level"
	// SeverityRuleLevel reads the rule's default level.
	SeverityRuleLevel SeveritySource = "rule_level"
	// SeverityRuleTag reads the first tag of the result's rule that the map
	// names (gosec puts severity in rule tags).
	SeverityRuleTag SeveritySource = "rule_tag"
	// SeverityResultProperty reads a named string property of the result
	// (Bandit's issue_severity).
	SeverityResultProperty SeveritySource = "result_property"
)

// SeverityMap is the closed map from the tool's values to a severity. A
// value the map does not name refuses that finding; it is never guessed.
type SeverityMap struct {
	Source   SeveritySource                 `json:"source"`
	Property string                         `json:"property,omitempty"`
	Levels   map[string]secfinding.Severity `json:"levels"`
}

// ConfidenceSource is where a result's confidence is read.
type ConfidenceSource string

// The ConfidenceSource values.
const (
	ConfidenceFixed          ConfidenceSource = "fixed"
	ConfidenceResultProperty ConfidenceSource = "result_property"
)

// ConfidenceMap chooses each finding's confidence: one fixed value, or a
// named result property through a closed map (Bandit's issue_confidence).
type ConfidenceMap struct {
	Source   ConfidenceSource                 `json:"source"`
	Fixed    secfinding.Confidence            `json:"fixed,omitempty"`
	Property string                           `json:"property,omitempty"`
	Levels   map[string]secfinding.Confidence `json:"levels,omitempty"`
}

// Placeholders are the only substitutions argv has, each a whole token.
const (
	PlaceholderTargets = "{targets_file}"
	PlaceholderOutput  = "{output_file}"
	PlaceholderProject = "{project_root}"
)

// envChoices is the closed environment table: the only NAME=VALUE entries a
// manifest may set (a Go driver needs a local toolchain and no module
// proxy; nothing here can carry a credential or redirect a loader).
var envChoices = []string{
	"CGO_ENABLED=0",
	"GOFLAGS=-mod=mod",
	"GOFLAGS=-mod=readonly",
	"GOPROXY=off",
	"GOTOOLCHAIN=local",
	"GOWORK=off",
	"NO_COLOR=1",
	"PYTHONDONTWRITEBYTECODE=1",
	"PYTHONNOUSERSITE=1",
	"SEMGREP_ENABLE_VERSION_CHECK=0",
	"SEMGREP_SEND_METRICS=off",
}

// EnvChoices returns the closed environment table.
func EnvChoices() []string { return append([]string(nil), envChoices...) }

// exitMeanings are the meanings an exit-code row may name.
var exitMeanings = []extrun.ExitMeaning{extrun.ExitResult, extrun.ExitClean, extrun.ExitFindings, extrun.ExitNoInput, extrun.ExitFailure}

// ExitMeanings returns the closed exit meaning set.
func ExitMeanings() []extrun.ExitMeaning { return append([]extrun.ExitMeaning(nil), exitMeanings...) }

// categories are the finding categories a custom driver may emit: code,
// infrastructure and CI findings, secrets and vulnerable dependencies. The
// agent, trust, provenance and gate categories stay Observer's own.
var categories = []secfinding.Category{
	policy.FindingCodeVuln, policy.FindingIaC, policy.FindingCIConfig,
	policy.FindingSecret, policy.FindingVulnerableDependency,
}

// Categories returns the categories a custom driver may emit.
func Categories() []secfinding.Category { return append([]secfinding.Category(nil), categories...) }

// Validation limits.
const (
	maxArgv       = 32
	maxArg        = 256
	maxCompanions = 4
	maxStderr     = 16
	maxStderrLen  = 128
	maxHosts      = 8
	maxMapEntries = 16
	maxExitCodes  = 16
	maxRules      = 64
	maxPath       = 512
)

var (
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	mapKeyRE  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,32}$`)
	ruleIDRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	hostRE    = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	braceRE   = regexp.MustCompile(`\{[^{}]*\}`)
	severitys = []secfinding.Severity{policy.FindingSeverityInfo, policy.FindingSeverityLow, policy.FindingSeverityMedium, policy.FindingSeverityHigh, policy.FindingSeverityCritical}
	confs     = []secfinding.Confidence{policy.FindingConfidenceLow, policy.FindingConfidenceMedium, policy.FindingConfidenceHigh}
)

// Options are the reader's settings.
type Options struct {
	// OrgApproved allows BlockingRules (an org catalog manifest only).
	OrgApproved bool
	// GOOS selects the path rules (Windows drive paths).
	GOOS string
}

// Parse reads one manifest file under every import check and validates it.
// Every error is a refusal with one plain sentence.
func Parse(data []byte, opt Options) (Manifest, error) {
	var m Manifest
	if err := strictDecode(data, &m); err != nil {
		return Manifest{}, err
	}
	if err := m.Validate(opt); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// FileDigest is the sha256 of the manifest file as shown in full before it
// is accepted.
func FileDigest(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// Digest is the sha256 of the manifest's canonical form (the struct
// marshalled with sorted map keys): the digest an org catalog pins and an
// accept confirms.
func (m Manifest) Digest() string {
	b, _ := json.Marshal(m)
	return FileDigest(b)
}

// isAbs reports whether p is an absolute path on goos.
func isAbs(goos, p string) bool { return extrun.IsAbs(goos, p) }

// cleanAbs refuses a path that is not absolute or not in clean form.
func cleanAbs(goos, field, p string) error {
	if err := displayable(field, p, maxPath, false); err != nil {
		return err
	}
	if !isAbs(goos, p) {
		return fmt.Errorf("%s must be an absolute path", field)
	}
	sep := "/"
	if goos == "windows" {
		sep = `\`
		if strings.Contains(p, "/") {
			return fmt.Errorf("%s must use backslashes on Windows", field)
		}
	}
	for _, seg := range strings.Split(p, sep)[1:] {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%s must be a clean path (no empty, . or .. element)", field)
		}
	}
	return nil
}

// Validate checks every field against its closed set and limits.
func (m Manifest) Validate(opt Options) error {
	if m.Schema != SchemaV1 {
		return fmt.Errorf("schema %q is not %q", clip(m.Schema, 40), SchemaV1)
	}
	if err := displayable("name", m.Name, 64, false); err != nil {
		return err
	}
	if err := displayable("version", m.Version, 32, false); err != nil {
		return err
	}
	if m.Template != "" {
		if _, ok := TemplateByID(m.Template); !ok {
			return fmt.Errorf("template %q is not a built-in template", clip(m.Template, 40))
		}
	}
	if err := cleanAbs(opt.GOOS, "executable", m.Executable); err != nil {
		return err
	}
	if m.ExecutableSHA256 != "" && !sha256RE.MatchString(m.ExecutableSHA256) {
		return errors.New("executable_sha256 must be 64 lower-case hex digits")
	}
	if err := m.validateArgv(); err != nil {
		return err
	}
	if err := m.Limits.validate(); err != nil {
		return err
	}
	if err := m.validateCompanions(opt.GOOS); err != nil {
		return err
	}
	if err := validateEnv(m.Env); err != nil {
		return err
	}
	if m.Cache != CacheNone && m.Cache != CachePerDriver {
		return fmt.Errorf("cache %q is not one of none, per_driver", clip(string(m.Cache), 40))
	}
	if err := m.validateSelfTest(); err != nil {
		return err
	}
	if len(m.UnknownStderr) > maxStderr {
		return fmt.Errorf("more than %d unknown_stderr patterns", maxStderr)
	}
	for i, p := range m.UnknownStderr {
		if err := displayable(fmt.Sprintf("unknown_stderr[%d]", i), p, maxStderrLen, false); err != nil {
			return err
		}
	}
	if err := validateExitCodes(m.ExitCodes); err != nil {
		return err
	}
	if err := validateNetwork(m.Network); err != nil {
		return err
	}
	if !slices.Contains(categories, secfinding.Category(m.Category)) {
		return fmt.Errorf("category %q is not one a custom driver may emit", clip(m.Category, 40))
	}
	if err := m.Severity.validate(); err != nil {
		return err
	}
	if err := m.Confidence.validate(); err != nil {
		return err
	}
	if len(m.BlockingRules) > 0 && !opt.OrgApproved {
		return errors.New("blocking_rules are allowed only in an org-approved manifest")
	}
	if len(m.BlockingRules) > maxRules {
		return fmt.Errorf("more than %d blocking_rules", maxRules)
	}
	for _, r := range m.BlockingRules {
		if !ruleIDRE.MatchString(r) {
			return fmt.Errorf("blocking rule %q is not a rule id", clip(r, 40))
		}
	}
	return nil
}

func (m Manifest) validateArgv() error {
	if len(m.Argv) > maxArgv {
		return fmt.Errorf("more than %d argv entries", maxArgv)
	}
	seen := map[string]int{}
	for i, a := range m.Argv {
		if err := displayable(fmt.Sprintf("argv[%d]", i), a, maxArg, true); err != nil {
			return err
		}
		phs := braceRE.FindAllString(a, -1)
		for _, ph := range phs {
			if ph != a {
				return fmt.Errorf("argv[%d]: the placeholder %s must be the whole argument", i, clip(ph, 40))
			}
			if ph != PlaceholderTargets && ph != PlaceholderOutput && ph != PlaceholderProject {
				return fmt.Errorf("argv[%d]: %s is not a placeholder", i, clip(ph, 40))
			}
			seen[ph]++
		}
		if len(phs) == 0 && strings.ContainsAny(a, "{}") {
			return fmt.Errorf("argv[%d]: a stray brace", i)
		}
	}
	for ph, n := range seen {
		if n > 1 {
			return fmt.Errorf("the placeholder %s is used %d times", ph, n)
		}
	}
	switch m.Input {
	case InputTargetsFile:
		if seen[PlaceholderTargets] != 1 {
			return errors.New("input targets_file needs {targets_file} in argv")
		}
	case InputStdin:
		if seen[PlaceholderTargets] != 0 {
			return errors.New("input stdin cannot also pass {targets_file}")
		}
	default:
		return fmt.Errorf("input %q is not one of targets_file, stdin", clip(string(m.Input), 40))
	}
	switch m.Output {
	case OutputSARIFFile:
		if seen[PlaceholderOutput] != 1 {
			return errors.New("output sarif_file needs {output_file} in argv")
		}
	case OutputSARIFStdout:
		if seen[PlaceholderOutput] != 0 {
			return errors.New("output sarif_stdout cannot also pass {output_file}")
		}
	default:
		return fmt.Errorf("output %q is not one of sarif_file, sarif_stdout", clip(string(m.Output), 40))
	}
	return nil
}

func (m Manifest) validateCompanions(goos string) error {
	if len(m.Companions) > maxCompanions {
		return fmt.Errorf("more than %d companions", maxCompanions)
	}
	seen := map[string]bool{}
	for i, c := range m.Companions {
		field := fmt.Sprintf("companions[%d].path", i)
		if err := cleanAbs(goos, field, c.Path); err != nil {
			return err
		}
		if seen[c.Path] || c.Path == m.Executable {
			return fmt.Errorf("%s is named twice", field)
		}
		seen[c.Path] = true
		if c.SHA256 != "" && !sha256RE.MatchString(c.SHA256) {
			return fmt.Errorf("companions[%d].sha256 must be 64 lower-case hex digits", i)
		}
		if _, ok := versionFormats[c.VersionFormat]; c.VersionFormat != "" && !ok {
			return fmt.Errorf("companions[%d].version_format %q is not in the closed set", i, clip(c.VersionFormat, 40))
		}
		if len(c.VersionArgv) > 4 {
			return fmt.Errorf("companions[%d].version_argv has more than 4 entries", i)
		}
		for j, a := range c.VersionArgv {
			if err := displayable(fmt.Sprintf("companions[%d].version_argv[%d]", i, j), a, 64, false); err != nil {
				return err
			}
			if strings.ContainsAny(a, "{}") {
				return fmt.Errorf("companions[%d].version_argv[%d] cannot hold a placeholder", i, j)
			}
		}
	}
	return nil
}

func validateEnv(env []string) error {
	names := map[string]bool{}
	for _, e := range env {
		if !slices.Contains(envChoices, e) {
			return fmt.Errorf("env %q is not in the closed environment table", clip(e, 40))
		}
		n, _, _ := strings.Cut(e, "=")
		if names[n] {
			return fmt.Errorf("env sets %s twice", n)
		}
		names[n] = true
	}
	return nil
}

func (m Manifest) validateSelfTest() error {
	if m.SelfTest == nil {
		return nil
	}
	if _, ok := fixtureByID(m.SelfTest.Fixture); !ok {
		return fmt.Errorf("self_test.fixture %q is not a built-in fixture", clip(m.SelfTest.Fixture, 40))
	}
	if len(m.SelfTest.ExpectRules) == 0 || len(m.SelfTest.ExpectRules) > maxMapEntries {
		return fmt.Errorf("self_test.expect_rules needs 1 to %d rule ids", maxMapEntries)
	}
	for _, r := range m.SelfTest.ExpectRules {
		if !ruleIDRE.MatchString(r) {
			return fmt.Errorf("self_test rule %q is not a rule id", clip(r, 40))
		}
	}
	return nil
}

func validateExitCodes(rows []ExitCode) error {
	if len(rows) == 0 || len(rows) > maxExitCodes {
		return fmt.Errorf("exit_codes needs 1 to %d rows", maxExitCodes)
	}
	seen := map[int]bool{}
	usable := false
	for _, r := range rows {
		if r.Code < 0 || r.Code > 255 {
			return fmt.Errorf("exit code %d is outside 0 to 255", r.Code)
		}
		if seen[r.Code] {
			return fmt.Errorf("exit code %d is named twice", r.Code)
		}
		seen[r.Code] = true
		if !slices.Contains(exitMeanings, r.Meaning) {
			return fmt.Errorf("exit meaning %q is not in the closed set", clip(string(r.Meaning), 40))
		}
		usable = usable || r.Meaning != extrun.ExitFailure
	}
	if !usable {
		return errors.New("exit_codes names no status that is a result")
	}
	return nil
}

// NetworkWords is the plain sentence a run and its label carry about the
// manifest's network: "" for none (the default), and for declared hosts a
// sentence that says the list is not enforced. Nothing restricts a run to
// its declared hosts: such a run cannot use the isolation component's
// no-network one-shot, so it has the machine's full network.
func NetworkWords(n Network) string {
	if n.Mode != NetworkHosts {
		return ""
	}
	return "network: the manifest declares the hosts " + strings.Join(n.Hosts, ", ") + ", and they are not enforced: the scanner can reach any host"
}

func validateNetwork(n Network) error {
	switch n.Mode {
	case NetworkNone:
		if len(n.Hosts) != 0 {
			return errors.New("network none cannot list hosts")
		}
	case NetworkHosts:
		if len(n.Hosts) == 0 || len(n.Hosts) > maxHosts {
			return fmt.Errorf("network hosts needs 1 to %d hosts", maxHosts)
		}
		for _, h := range n.Hosts {
			lh := strings.ToLower(h)
			switch {
			case isIPLiteral(h):
				return fmt.Errorf("network host %q is an IP address", clip(h, 40))
			case !hostRE.MatchString(h), lh == "localhost",
				strings.HasSuffix(lh, ".localhost"), strings.HasSuffix(lh, ".local"), strings.HasSuffix(lh, ".internal"):
				return fmt.Errorf("network host %q is not a public DNS name", clip(h, 40))
			}
		}
	default:
		return fmt.Errorf("network mode %q is not one of none, hosts", clip(n.Mode, 40))
	}
	return nil
}

func (s SeverityMap) validate() error {
	switch s.Source {
	case SeverityLevel, SeverityRuleLevel, SeverityRuleTag:
		if s.Property != "" {
			return errors.New("severity_map.property is only for the result_property source")
		}
	case SeverityResultProperty:
		if !mapKeyRE.MatchString(s.Property) {
			return errors.New("severity_map.property is not a property name")
		}
	default:
		return fmt.Errorf("severity_map.source %q is not in the closed set", clip(string(s.Source), 40))
	}
	return validateMap("severity_map.levels", s.Levels, severitys)
}

func (c ConfidenceMap) validate() error {
	switch c.Source {
	case ConfidenceFixed:
		if !slices.Contains(confs, c.Fixed) || c.Property != "" || len(c.Levels) != 0 {
			return errors.New("confidence_map fixed needs one confidence and nothing else")
		}
		return nil
	case ConfidenceResultProperty:
		if !mapKeyRE.MatchString(c.Property) || c.Fixed != "" {
			return errors.New("confidence_map.property is not a property name")
		}
		return validateMap("confidence_map.levels", c.Levels, confs)
	default:
		return fmt.Errorf("confidence_map.source %q is not in the closed set", clip(string(c.Source), 40))
	}
}

// validateMap checks a closed value map: 1 to maxMapEntries keys of the
// key charset, every value in allowed.
func validateMap[V comparable](field string, m map[string]V, allowed []V) error {
	if len(m) == 0 || len(m) > maxMapEntries {
		return fmt.Errorf("%s needs 1 to %d entries", field, maxMapEntries)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !mapKeyRE.MatchString(k) {
			return fmt.Errorf("%s key %q is not allowed", field, clip(k, 40))
		}
		if !slices.Contains(allowed, m[k]) {
			return fmt.Errorf("%s %q maps to %v, which is not allowed", field, clip(k, 40), m[k])
		}
	}
	return nil
}

// ExitTable is the manifest's exit-code table as the runner's engine rows.
func (m Manifest) ExitTable() []extrun.ExitCodeRow {
	out := make([]extrun.ExitCodeRow, 0, len(m.ExitCodes))
	for _, r := range m.ExitCodes {
		out = append(out, extrun.ExitCodeRow{Code: r.Code, Meaning: r.Meaning})
	}
	return out
}

// isIPLiteral reports an IP address (with or without a zone or brackets).
func isIPLiteral(h string) bool {
	_, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil
}
