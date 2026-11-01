package diag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookdigest"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// CaptureIntegritySignals is the content-free result of checking whether the
// node's registered capture hooks still match its recorded local posture.
// Risks are positive observations; Unknown contains checks that could not
// produce a result. Neither slice contains paths, commands, errors, or values.
// Items locates each risk on a tool and a home-relative file label (T-847);
// orgcontract.CaptureRiskItem documents its content floor. ItemsOmitted is how
// many located risks the item bound left out of Items (T-873); the bound keeps
// the most actionable ones (orgcontract.CaptureRiskItemLess).
type CaptureIntegritySignals struct {
	Risks        []string
	Unknown      []string
	Items        []orgcontract.CaptureRiskItem
	ItemsOmitted int
}

type captureRegistryEntry struct {
	SHA256      string `json:"sha256"`
	DigestScope string `json:"digest_scope"`
	HooksSHA256 string `json:"hooks_sha256"`
	BinaryPath  string `json:"binary_path"`
	LastResult  string `json:"last_result"`
	// Tool is the registration target that wrote the entry (T-847). Empty
	// on an entry written before the field existed.
	Tool string `json:"tool"`
	// LastRepairedAt / LastRepairedEvents record the newest repair
	// auto-registration made to the file (hook.Registry.RecordRegistration).
	LastRepairedAt     string   `json:"last_repaired_at"`
	LastRepairedEvents []string `json:"last_repaired_events"`
	// LastRepairedCopy is where that repair kept the bytes it replaced
	// (T-884, hook.LastRepairedCopyKey); empty when it kept none.
	LastRepairedCopy string `json:"last_repaired_copy"`
	// LastErrorAt records the newest failed registration pass on the file
	// (T-887); a later successful pass keeps it.
	LastErrorAt string `json:"last_error_at"`
}

// ExpectedHook is one hook registration target the node's own
// auto-registration owns on this host, as a dry run of that registration
// sees it (cmd/observer builds the list through hook.Registry.Probe). Drift
// names the events a real registration would add or rewrite: a non-empty
// Drift means a registered hook is missing or weakened.
type ExpectedHook struct {
	Tool       string
	ConfigPath string
	Drift      []string
}

// CaptureIntegrityOptions are the inputs InspectCaptureIntegrityWith takes
// beyond the home directory. The zero value plus BinaryPath reproduces
// InspectCaptureIntegrity.
type CaptureIntegrityOptions struct {
	// BinaryPath is the running observer as a hook registration names it:
	// the registration command (the npm / pip launcher when one resolves to
	// this install, else the real path), the value `observer doctor`
	// compares with too (T-874).
	BinaryPath string
	// RealBinaryPath is the running binary with symlinks resolved; a
	// registration that names it is the same observer. Empty means only
	// BinaryPath is known.
	RealBinaryPath string
	// Expected lists the targets the node registers (see ExpectedHook).
	// When it is non-empty a missing registry, or a target without a
	// registry entry, is a risk rather than an unknown: the node knows it
	// has hooks to account for (audit c3).
	Expected []ExpectedHook
	// Now and RepairWindow bound how long a recorded repair is reported as
	// hook_repaired, and a recorded failure that has since cleared as
	// hook_registration_failed (T-887). A zero Now disables both reports; a
	// zero RepairWindow means DefaultRepairWindow.
	Now          time.Time
	RepairWindow time.Duration
}

// DefaultRepairWindow is how long a recorded hook repair stays in the report.
const DefaultRepairWindow = 24 * time.Hour

// HookRegistryTool is the tool label the registry file itself is reported
// under (it belongs to Observer, not to an AI tool).
const HookRegistryTool = "observer"

// hookEntryMatches reports whether body still matches a hook_checksums.json
// entry. A credential-bearing file's entry (digest_scope "hooks", the D-268
// exception) carries a digest of the hooks subtree only, never a whole-file
// hash, so it is compared with internal/hookdigest; any other entry with the
// whole-file SHA-256.
func hookEntryMatches(path string, body []byte, wholeSHA, scope, hooksSHA string) bool {
	if scope == hookdigest.Scope {
		got, err := hookdigest.HooksSubtree(path, body)
		return err == nil && hooksSHA != "" && got == hooksSHA
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]) == wholeSHA
}

const (
	maxCaptureRegistryBytes = 1 << 20
	maxCaptureConfigBytes   = 4 << 20
)

// InspectCaptureIntegrity reads the hook registry and Codex trust posture and
// returns only closed labels from orgcontract. A whole-config checksum change
// is reported as review-required evidence because tool config files also hold
// unrelated settings; it is never classified as proof of capture bypass.
func InspectCaptureIntegrity(homeDir, binaryPath string) CaptureIntegritySignals {
	return InspectCaptureIntegrityWith(homeDir, CaptureIntegrityOptions{BinaryPath: binaryPath})
}

// captureCollector accumulates labels and located items for one inspection.
type captureCollector struct {
	homeDir string
	risks   map[string]bool
	unknown map[string]bool
	items   map[string]orgcontract.CaptureRiskItem
}

// risk records a positive observation, located on tool and path when known.
func (c *captureCollector) risk(label, tool, path string, events []string) {
	c.riskAct(label, tool, path, events, "", "")
}

// riskAt is risk for an act that carries its time (T-886): at is the RFC3339
// time the act happened, which the organization reads as the identity of
// this occurrence, so a repeat of the act is a new event.
func (c *captureCollector) riskAt(label, tool, path string, events []string, at string) {
	c.riskAct(label, tool, path, events, at, "")
}

// riskAct is riskAt for an act that also kept the bytes it replaced at
// keptCopy (T-884, a hook repair): the item carries the copy under the same
// label rules as the file.
func (c *captureCollector) riskAct(label, tool, path string, events []string, at, keptCopy string) {
	c.risks[label] = true
	it := orgcontract.CaptureRiskItem{
		Risk: label, Tool: tool, File: RiskFileLabel(c.homeDir, path), Events: events,
		At: at, KeptCopy: RiskFileLabel(c.homeDir, keptCopy),
	}
	if prior, ok := c.items[it.Key()]; ok {
		it.Events = append(append([]string{}, prior.Events...), events...)
		if it.At == "" {
			it.At = prior.At
		}
		if it.KeptCopy == "" {
			it.KeptCopy = prior.KeptCopy
		}
	}
	c.items[it.Key()] = it
}

// InspectCaptureIntegrityWith is InspectCaptureIntegrity with the T-847
// inputs: the targets the node is expected to have registered (with their
// dry-run drift) and the repair-report window. Every risk observed on a hook
// artifact is also returned as a located item naming the tool and the file.
func InspectCaptureIntegrityWith(homeDir string, opts CaptureIntegrityOptions) CaptureIntegritySignals {
	c := &captureCollector{
		homeDir: homeDir,
		risks:   map[string]bool{},
		unknown: map[string]bool{},
		items:   map[string]orgcontract.CaptureRiskItem{},
	}
	registryPath := filepath.Join(homeDir, ".observer", "hook_checksums.json")
	var entries map[string]captureRegistryEntry
	registryRead := false
	raw, err := regularfile.Read(registryPath, maxCaptureRegistryBytes)
	switch {
	case err != nil && errors.Is(err, os.ErrNotExist) && len(opts.Expected) > 0:
		// The node registers hooks here, so a missing registry is a positive
		// observation, not the absence of one (audit c3).
		c.risk(orgcontract.CaptureRiskHookRegistryMissing, HookRegistryTool, registryPath, nil)
	case err != nil && errors.Is(err, os.ErrNotExist):
		c.unknown[orgcontract.CaptureUnknownRegistryMissing] = true
	case err != nil:
		c.unknown[orgcontract.CaptureUnknownRegistryUnreadable] = true
	default:
		if uerr := json.Unmarshal(raw, &entries); uerr != nil {
			c.unknown[orgcontract.CaptureUnknownRegistryInvalid] = true
			entries = nil
			break
		}
		registryRead = true
		if len(entries) == 0 && len(opts.Expected) == 0 {
			c.unknown[orgcontract.CaptureUnknownRegistryEmpty] = true
			break
		}
		inspectCaptureRegistryEntries(c, entries, opts)
	}
	inspectExpectedHooks(c, entries, registryRead, opts.Expected)

	trust := checkCodexHookTrust(homeDir)
	if trust.Status == StatusWarn || trust.Status == StatusFail {
		switch {
		case len(trust.Details) > 0 && strings.HasPrefix(trust.Details[0], "untrusted:"):
			c.risk(orgcontract.CaptureRiskCodexHookUntrusted, "codex", filepath.Join(homeDir, ".codex", "config.toml"), nil)
		case len(trust.Details) > 0 && strings.HasPrefix(trust.Details[0], "not registered:"):
			// Every present entry runs; an event a newer Observer adds is
			// a registration gap, not a trust risk or an unknown.
		default:
			c.unknown[orgcontract.CaptureUnknownCodexTrust] = true
		}
	}

	items, omitted := orgcontract.NormalizeCaptureRiskItemsCounted(sortedCaptureItems(c.items))
	return CaptureIntegritySignals{
		Risks:        sortedCaptureLabels(c.risks),
		Unknown:      sortedCaptureLabels(c.unknown),
		Items:        items,
		ItemsOmitted: omitted,
	}
}

// inspectExpectedHooks reports, for every target the node registers, a dry
// run that would change the artifact (missing or weakened wiring), and a
// target the registry holds no entry for. registryRead is false when the
// registry could not be read at all, which is already reported once.
func inspectExpectedHooks(c *captureCollector, entries map[string]captureRegistryEntry, registryRead bool, expected []ExpectedHook) {
	for _, e := range expected {
		if len(e.Drift) > 0 {
			c.risk(orgcontract.CaptureRiskHookRegistrationDrift, e.Tool, e.ConfigPath, e.Drift)
		}
		if !registryRead || e.ConfigPath == "" {
			continue
		}
		if _, ok := entries[e.ConfigPath]; !ok {
			c.risk(orgcontract.CaptureRiskHookRegistryEntryMissing, e.Tool, e.ConfigPath, nil)
		}
	}
}

func inspectCaptureRegistryEntries(c *captureCollector, entries map[string]captureRegistryEntry, opts CaptureIntegrityOptions) {
	binaryPath := opts.BinaryPath
	if strings.TrimSpace(binaryPath) == "" {
		c.unknown[orgcontract.CaptureUnknownBinaryPath] = true
	}
	toolFor := expectedToolByPath(opts.Expected)
	for configPath, entry := range entries {
		tool := entry.Tool
		if tool == "" {
			tool = toolFor[configPath]
		}
		if entry.LastResult == "error" {
			c.risk(orgcontract.CaptureRiskHookRegistrationError, tool, configPath, nil)
		} else if recentAct(entry.LastErrorAt, opts) {
			// T-887: the error cleared before this report. Without the
			// record, a refusal fixed while the organization was unreachable
			// never reached it.
			c.riskAt(orgcontract.CaptureRiskHookRegistrationFailed, tool, configPath, nil, entry.LastErrorAt)
		}
		body, err := regularfile.Read(configPath, maxCaptureConfigBytes)
		switch {
		case err != nil:
			if errors.Is(err, os.ErrNotExist) {
				c.risk(orgcontract.CaptureRiskHookConfigMissing, tool, configPath, nil)
			} else {
				c.unknown[orgcontract.CaptureUnknownConfigUnreadable] = true
			}
		case strings.TrimSpace(entry.SHA256) == "" && strings.TrimSpace(entry.HooksSHA256) == "":
			c.unknown[orgcontract.CaptureUnknownChecksumMissing] = true
		default:
			if !hookEntryMatches(configPath, body, entry.SHA256, entry.DigestScope, entry.HooksSHA256) {
				c.risk(orgcontract.CaptureRiskHookConfigChanged, tool, configPath, nil)
			}
		}

		switch {
		case strings.TrimSpace(entry.BinaryPath) == "":
			c.unknown[orgcontract.CaptureUnknownRecordedBinary] = true
		case strings.TrimSpace(binaryPath) != "" &&
			!HookBinaryMatches(entry.BinaryPath, HookBinaryIdentity{Command: binaryPath, Real: opts.RealBinaryPath}):
			// T-874: the same equivalence `observer doctor` uses
			// (hook_binary.go), so a launcher and the binary it starts are
			// one observer, and only a different or vanished binary is a
			// mismatch.
			c.risk(orgcontract.CaptureRiskHookBinaryMismatch, tool, configPath, nil)
		}

		if events, ok := recentRepair(entry, opts); ok {
			c.riskAct(orgcontract.CaptureRiskHookRepaired, tool, configPath, events, entry.LastRepairedAt, entry.LastRepairedCopy)
		}
	}
}

// recentRepair returns the events of a repair recorded within the window.
func recentRepair(entry captureRegistryEntry, opts CaptureIntegrityOptions) ([]string, bool) {
	if !recentAct(entry.LastRepairedAt, opts) {
		return nil, false
	}
	return entry.LastRepairedEvents, true
}

// recentAct reports whether an act recorded at stamp (RFC3339) is inside the
// report window (opts.RepairWindow, DefaultRepairWindow when zero). A zero
// opts.Now, an empty stamp or one that does not parse is not recent.
func recentAct(stamp string, opts CaptureIntegrityOptions) bool {
	if opts.Now.IsZero() || stamp == "" {
		return false
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return false
	}
	window := opts.RepairWindow
	if window <= 0 {
		window = DefaultRepairWindow
	}
	return opts.Now.Sub(at) <= window
}

// expectedToolByPath maps an expected target's config path to its tool, the
// fallback for a registry entry written before entries carried their tool.
func expectedToolByPath(expected []ExpectedHook) map[string]string {
	out := make(map[string]string, len(expected))
	for _, e := range expected {
		if e.ConfigPath != "" {
			out[e.ConfigPath] = e.Tool
		}
	}
	return out
}

// RiskFileLabel renders path as the label the content floor of
// orgcontract.CaptureRiskItem allows: "~/" plus the path under homeDir,
// "~win/" plus the path under a Windows user home (C:\Users\<name> or
// /mnt/<drive>/Users/<name>), or "?/" plus the last two path elements. The
// user name is never part of the label. An empty path yields "".
func RiskFileLabel(homeDir, path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	slash := strings.ReplaceAll(path, `\`, "/")
	if homeDir != "" {
		home := strings.TrimSuffix(strings.ReplaceAll(homeDir, `\`, "/"), "/")
		if rel, ok := strings.CutPrefix(slash, home+"/"); ok && rel != "" {
			return "~/" + rel
		}
	}
	parts := strings.Split(slash, "/")
	for i := 0; i+2 < len(parts); i++ {
		if strings.EqualFold(parts[i], "Users") && parts[i+1] != "" {
			if rel := strings.Join(parts[i+2:], "/"); rel != "" {
				return "~win/" + rel
			}
		}
	}
	tail := parts
	if len(tail) > 2 {
		tail = tail[len(tail)-2:]
	}
	return "?/" + strings.TrimPrefix(strings.Join(tail, "/"), "/")
}

func sortedCaptureItems(set map[string]orgcontract.CaptureRiskItem) []orgcontract.CaptureRiskItem {
	out := make([]orgcontract.CaptureRiskItem, 0, len(set))
	for _, it := range set {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

func sortedCaptureLabels(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for label := range set {
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}
