package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Managed policy-family backfill (review C156-04, T-354; release-blocking).
//
// The enrolment write (ensureManagedPolicyBlock) runs ONCE, when the grant is
// accepted, and never rewrites keys that already exist. So a managed node
// that enrolled before node.features was mapped to any authority never
// listed it in [org_client.policy].accept_families, and every org feature
// lock, tools.disallow list and G8 tool or feature grant stayed inert on that
// node no matter how often the org republished. The same holds for any
// family a future build maps.
//
// The backfill closes that, once per family per enrolment identity, at daemon
// start (before anything loads the config, because the policy lists are read
// once at start):
//
//   - only a MANAGED enrolment holding an accepted, managed-consent, unexpired
//     grant qualifies (an individual or BYO node is never touched: its lists
//     are its operator's own opt-in);
//   - the families owed are govern.ManagedFamilyBackfill over the grant's
//     govern.ManagedGovernedFamilies (only those linked in this build,
//     linkedManagedFamilies), the node's current accept_families and the
//     record of what this enrolment was already offered;
//   - the write is additive (existing entries and order are kept, nothing is
//     ever removed) and is checked by re-loading the config; a result that
//     does not load is rolled back byte for byte;
//   - the record (managed-policy-families.json beside the DB) is keyed by the
//     enrolment's org key and generation, so a family a developer removes
//     after it was offered is not re-added at the next start, while a
//     re-enrolment starts a fresh record.

// managedFamiliesRecordName is the node-local record of the families a
// managed enrolment has been offered by the backfill.
const managedFamiliesRecordName = "managed-policy-families.json"

// managedFamiliesRecord is that record's shape.
type managedFamiliesRecord struct {
	OrgKey     string   `json:"org_key"`
	Generation int64    `json:"generation"`
	Offered    []string `json:"offered"`
	UpdatedAt  string   `json:"updated_at"`
}

// managedPolicyFacts is what the backfill needs from the store, resolved at
// the boundary so the decision and the file write stay testable without a DB.
type managedPolicyFacts struct {
	OrgKey     string
	Generation int64
	// Governed is govern.ManagedGovernedFamilies of the live grant, kept to
	// the families linked in this build (linkedManagedFamilies).
	Governed []string
}

// loadManagedPolicyFacts reads the enrolment and its grant. ok=false means
// the node does not qualify (not enrolled, not managed, no grant, not a
// managed-class consent, or a lapsed grant).
func loadManagedPolicyFacts(ctx context.Context, st *store.Store, now time.Time) (managedPolicyFacts, bool, error) {
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		return managedPolicyFacts{}, false, err
	}
	// Managed by enrolment or by its org's switch to enterprise (P-204).
	if managed, merr := orgclient.NodeManagedFor(ctx, st, enr); merr != nil {
		return managedPolicyFacts{}, false, merr
	} else if !managed {
		return managedPolicyFacts{}, false, nil
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	row, ok, err := st.LoadEnrolmentGrant(ctx, orgKey)
	if err != nil || !ok {
		return managedPolicyFacts{}, false, err
	}
	if !govern.ManagedConsent(row.ConsentMode) {
		return managedPolicyFacts{}, false, nil
	}
	if !row.ExpiresAt.IsZero() && now.After(row.ExpiresAt) {
		return managedPolicyFacts{}, false, nil
	}
	governed := linkedManagedFamilies(govern.ManagedGovernedFamilies(row.Authority))
	if len(governed) == 0 {
		return managedPolicyFacts{}, false, nil
	}
	return managedPolicyFacts{OrgKey: orgKey, Generation: row.Generation, Governed: governed}, true, nil
}

// linkedManagedFamilies keeps the families whose compiler is linked in this
// build (policyfam.IsFamilyLinked). A family whose compiler an optional
// component adds (security.scanning and terminals.isolation, until the
// security and sandbox lanes link theirs) is never written into config.toml
// by a build that cannot compile it: an older binary that does not know the
// name refuses the whole config, and an update rollback restores the binary
// and the database but not config.toml (audit SHR-KIT finding 1). Such a
// family is not recorded as offered either, so the first build that links
// it offers it once, at its first start. Both the enrolment write
// (managedPolicyFamiliesToWrite) and the start-time backfill read through it.
func linkedManagedFamilies(families []string) []string {
	var out []string
	for _, f := range families {
		if policyfam.IsFamilyLinked(f) && managedFamilyWriteHeld[f] == "" {
			out = append(out, f)
		}
	}
	return out
}

// managedFamilyWriteHeld lists linked families the managed accept-list write
// still holds back, each with its reason. Empty since the SEC-E merge
// (plans decision P-047): a released binary refuses a config.toml whose
// accept_families or preauthorize_enforce names a family it does not know,
// also after a manual downgrade, but ignores a key it does not know. So the
// writers put every family a released binary does not know
// (config.SplitPolicyFamilies: security.scanning, terminals.isolation and
// every later one) into accept_module_families / preauthorize_module_enforce
// instead, and never touch the old keys for it; and every update rollback
// also restores the pre-apply config.toml (update_apply.go). A family that
// must be held again is listed here with its reason.
var managedFamilyWriteHeld = map[string]string{}

// readManagedFamiliesRecord returns the record for (orgKey, generation), or
// have=false when none exists or it belongs to another enrolment identity.
// An unreadable or corrupt record is treated as absent: the fail direction
// is "offer the governed families", which is the managed-consent default.
func readManagedFamiliesRecord(path, orgKey string, generation int64) (managedFamiliesRecord, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return managedFamiliesRecord{}, false
	}
	var rec managedFamiliesRecord
	if json.Unmarshal(raw, &rec) != nil {
		return managedFamiliesRecord{}, false
	}
	if rec.OrgKey != orgKey || rec.Generation != generation {
		return managedFamiliesRecord{}, false
	}
	return rec, true
}

// managedBackfillResult is what one backfill did.
type managedBackfillResult struct {
	Added []string
	// RecordWritten reports whether the offered-families record changed.
	RecordWritten bool
}

// backfillManagedPolicyFamilies is the I/O-light core: given the facts, the
// config path, the node's current lists and the record path, it adds the
// owed families to both keys and records what this enrolment was offered.
func backfillManagedPolicyFamilies(cfgPath, recordPath string, facts managedPolicyFacts, policy config.OrgClientPolicyConfig, now time.Time) (managedBackfillResult, error) {
	rec, have := readManagedFamiliesRecord(recordPath, facts.OrgKey, facts.Generation)
	owed := govern.ManagedFamilyBackfill(facts.Governed, rec.Offered, have, policy.AcceptedFamilies())
	var res managedBackfillResult
	if len(owed) > 0 {
		if err := addManagedPolicyFamilies(cfgPath, policy, owed); err != nil {
			return res, err
		}
		res.Added = owed
	}
	offered := managedFamiliesUnion(rec.Offered, facts.Governed)
	if have && strings.Join(managedFamiliesUnion(rec.Offered, nil), ",") == strings.Join(offered, ",") {
		return res, nil
	}
	next := managedFamiliesRecord{OrgKey: facts.OrgKey, Generation: facts.Generation, Offered: offered, UpdatedAt: now.UTC().Format(time.RFC3339)}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return res, err
	}
	if err := os.MkdirAll(filepath.Dir(recordPath), 0o755); err != nil {
		return res, err
	}
	if err := fsatomic.WriteFile(recordPath, append(raw, '\n'), fsatomic.Options{FilePerm: 0o600}); err != nil {
		return res, err
	}
	res.RecordWritten = true
	return res, nil
}

// managedFamiliesUnion returns the sorted, deduplicated union of a and b.
func managedFamiliesUnion(a, b []string) []string {
	set := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		if s != "" {
			set[s] = true
		}
	}
	for _, s := range b {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// appendMissingFamilies returns cur with every entry of add that cur lacks
// appended, keeping cur's own order.
func appendMissingFamilies(cur, add []string) []string {
	have := make(map[string]bool, len(cur))
	out := append([]string(nil), cur...)
	for _, s := range cur {
		have[s] = true
	}
	for _, s := range add {
		if !have[s] {
			have[s] = true
			out = append(out, s)
		}
	}
	return out
}

// addManagedPolicyFamilies merges add into the [org_client.policy] keys of
// the file at path, additively: a missing table is appended, a missing key
// is inserted after the header, an existing key's value (single- or
// multi-line) is replaced by its old entries plus add. A family a released
// binary knows goes to accept_families / preauthorize_enforce; every other
// one to accept_module_families / preauthorize_module_enforce
// (config.SplitPolicyFamilies), and a pair with nothing to add is left
// byte for byte. The result is re-loaded through config.Load; if it does
// not load, the original bytes are restored and the load error returned.
func addManagedPolicyFamilies(path string, policy config.OrgClientPolicyConfig, add []string) error {
	orig, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(string(orig), "\n")
	headerIdx := managedPolicyHeaderLineIndex(lines)
	if headerIdx == -1 {
		if err := appendManagedPolicyBlock(path, add); err != nil {
			return err
		}
		return verifyManagedPolicyWrite(path, orig)
	}
	addOld, addModule := config.SplitPolicyFamilies(add)
	pairs := []struct {
		acceptKey, preauthKey string
		accept, preauth, add  []string
	}{
		{"accept_families", "preauthorize_enforce", policy.AcceptFamilies, policy.PreauthorizeEnforce, addOld},
		{"accept_module_families", "preauthorize_module_enforce", policy.AcceptModuleFamilies, policy.PreauthorizeModuleEnforce, addModule},
	}
	for _, p := range pairs {
		if len(p.add) == 0 {
			continue
		}
		lines = setManagedPolicyKey(lines, managedPolicyHeaderLineIndex(lines), p.preauthKey, quotedTomlStringList(appendMissingFamilies(p.preauth, p.add)))
		lines = setManagedPolicyKey(lines, managedPolicyHeaderLineIndex(lines), p.acceptKey, quotedTomlStringList(appendMissingFamilies(p.accept, p.add)))
	}
	if err := fsatomic.WriteFile(path, []byte(strings.Join(lines, "\n")), fsatomic.Options{FilePerm: 0o600}); err != nil {
		return err
	}
	return verifyManagedPolicyWrite(path, orig)
}

// verifyManagedPolicyWrite re-loads the config; on failure it restores the
// original bytes (or removes a file that did not exist before).
func verifyManagedPolicyWrite(path string, orig []byte) error {
	if _, err := config.Load(config.LoadOptions{GlobalPath: path}); err != nil {
		if orig == nil {
			_ = os.Remove(path)
		} else {
			_ = fsatomic.WriteFile(path, orig, fsatomic.Options{FilePerm: 0o600})
		}
		return fmt.Errorf("the backfilled config did not load, so it was restored: %w", err)
	}
	return nil
}

// setManagedPolicyKey sets key = value inside the table whose header is at
// headerIdx: an existing assignment (including a multi-line array) is
// replaced in place by one line; a missing one is inserted right after the
// header. Every other line is kept byte for byte.
func setManagedPolicyKey(lines []string, headerIdx int, key, value string) []string {
	end := tableSectionEnd(lines, headerIdx+1)
	for i := headerIdx + 1; i < end; i++ {
		if !sectionDeclaresKey([]string{lines[i]}, key) {
			continue
		}
		last := arrayAssignmentEnd(lines, i, end)
		out := make([]string, 0, len(lines))
		out = append(out, lines[:i]...)
		out = append(out, key+" = "+value)
		out = append(out, lines[last+1:]...)
		return out
	}
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:headerIdx+1]...)
	out = append(out, key+" = "+value)
	out = append(out, lines[headerIdx+1:]...)
	return out
}

// arrayAssignmentEnd returns the index of the line that closes the value
// starting on line start: start itself for a one-line value, or the line
// holding the bracket that closes a multi-line array. Brackets inside quoted
// strings and comments are ignored. It never looks past end-1.
func arrayAssignmentEnd(lines []string, start, end int) int {
	depth := 0
	opened := false
	for i := start; i < end; i++ {
		ln := lines[i]
		if i == start {
			if eq := strings.Index(ln, "="); eq >= 0 {
				ln = ln[eq+1:]
			}
		}
		var quote byte
		for j := 0; j < len(ln); j++ {
			c := ln[j]
			switch {
			case quote != 0:
				if c == '\\' && quote == '"' {
					j++
				} else if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '#':
				j = len(ln)
			case c == '[':
				depth++
				opened = true
			case c == ']':
				depth--
			}
		}
		if !opened || depth <= 0 {
			return i
		}
	}
	return end - 1
}

// reconcileManagedPolicyAtStart is the one daemon-start call site of the
// backfill (cmd/observer/start.go, right after the config auto-migrate and
// before anything loads the config). Fail-open: any error is a WARN and the
// daemon starts with the config as it was. It never creates a database.
func reconcileManagedPolicyAtStart(ctx context.Context, configPath string, errOut io.Writer) {
	cfgPath, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return
	}
	if _, statErr := os.Stat(cfg.Observer.DBPath); statErr != nil {
		return
	}
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	now := time.Now()
	facts, ok, err := loadManagedPolicyFacts(ctx, store.New(database), now)
	if err != nil || !ok {
		return
	}
	recordPath := filepath.Join(filepath.Dir(cfg.Observer.DBPath), managedFamiliesRecordName)
	res, err := backfillManagedPolicyFamilies(cfgPath, recordPath, facts, cfg.OrgClient.Policy, now)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintf(errOut, "WARN managed policy families: %v (continuing with the config as it was)\n", err)
		}
		return
	}
	if len(res.Added) > 0 {
		fmt.Fprintf(errOut, "managed enrolment: added %s to [org_client.policy] (accept_families and preauthorize_enforce, or their _module_ twins for a module family) in %s "+
			"(families your accepted managed grant governs that this machine had not been offered yet)\n",
			quotedTomlStringList(res.Added), cfgPath)
	}
}
