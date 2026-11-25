package diag

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// hook_registrations.go holds the recorded hook-configuration checks of
// `observer doctor`: the config checksums (hooks.checksums) and whether each
// hook command still names the running binary (hooks.binary). Moved out of
// doctor.go unchanged.

// checkHookChecksums reads ~/.observer/hook_checksums.json and verifies
// each recorded config file still hashes to the expected value. Drift is
// reported as StatusWarn so the user can decide whether to re-run init.
func checkHookChecksums(homeDir string) Check {
	csPath := filepath.Join(homeDir, ".observer", "hook_checksums.json")
	raw, err := os.ReadFile(csPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Check{Name: "hooks.checksums", Status: StatusWarn, Message: "no hook_checksums.json yet - run " + remedy.Quote(initAll) + " first", Remediations: []remedy.Remediation{initAll}}
		}
		return Check{Name: "hooks.checksums", Status: StatusFail, Message: "read checksums: " + err.Error()}
	}
	var entries map[string]struct {
		SHA256      string `json:"sha256"`
		DigestScope string `json:"digest_scope"`
		HooksSHA256 string `json:"hooks_sha256"`
		Registered  string `json:"registered"`
		BinaryPath  string `json:"binary_path"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return Check{Name: "hooks.checksums", Status: StatusFail, Message: "parse checksums: " + err.Error()}
	}
	if len(entries) == 0 {
		return Check{Name: "hooks.checksums", Status: StatusWarn, Message: "no hooks registered"}
	}

	var (
		drift   []string
		missing []string
		matched int
	)
	for path, want := range entries {
		body, err := os.ReadFile(path)
		if err != nil {
			missing = append(missing, path+": "+err.Error())
			continue
		}
		if !hookEntryMatches(path, body, want.SHA256, want.DigestScope, want.HooksSHA256) {
			drift = append(drift, path)
			continue
		}
		matched++
	}

	switch {
	case len(missing) > 0:
		return Check{
			Name: "hooks.checksums", Status: StatusFail,
			Message: fmt.Sprintf("%d config file(s) missing", len(missing)),
			Details: missing,
		}
	case len(drift) > 0:
		return Check{
			Name: "hooks.checksums", Status: StatusWarn,
			Message:      fmt.Sprintf("%d config file(s) modified externally - re-run %s to refresh", len(drift), remedy.Quote(initAll)),
			Details:      drift,
			Remediations: []remedy.Remediation{initAll},
		}
	}
	return Check{Name: "hooks.checksums", Status: StatusOK, Message: fmt.Sprintf("%d config(s) match recorded checksums", matched)}
}

// checkHookCommandsBinary looks at every recorded hook config and verifies
// the command it points to is the running observer binary. Mismatch
// usually means the binary was moved after `observer init`. binaryPath is
// the registration command and realBinary the running binary; the match is
// HookBinaryMatches, the one rule table the managed-integrity probe uses too
// (T-874).
func checkHookCommandsBinary(homeDir, binaryPath, realBinary string) Check {
	if binaryPath == "" {
		return Check{Name: "hooks.binary", Status: StatusWarn, Message: "binary path unknown"}
	}
	csPath := filepath.Join(homeDir, ".observer", "hook_checksums.json")
	raw, err := os.ReadFile(csPath)
	if err != nil {
		return Check{Name: "hooks.binary", Status: StatusOK, Message: "no checksums to verify"}
	}
	var entries map[string]struct {
		BinaryPath string `json:"binary_path"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return Check{Name: "hooks.binary", Status: StatusFail, Message: "parse checksums: " + err.Error()}
	}
	var drift []string
	for path, e := range entries {
		if e.BinaryPath != "" && !HookBinaryMatches(e.BinaryPath, HookBinaryIdentity{Command: binaryPath, Real: realBinary}) {
			drift = append(drift, fmt.Sprintf("%s: registered=%s running=%s", path, e.BinaryPath, binaryPath))
		}
	}
	sort.Strings(drift)
	if len(drift) > 0 {
		return Check{
			Name: "hooks.binary", Status: StatusWarn,
			Message:      fmt.Sprintf("%d hook(s) point at a different binary path - re-run %s", len(drift), remedy.Quote(initAll)),
			Details:      drift,
			Remediations: []remedy.Remediation{initAll},
		}
	}
	return Check{Name: "hooks.binary", Status: StatusOK, Message: "all hooks point at the running binary"}
}
