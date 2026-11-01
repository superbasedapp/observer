package hook

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/codextrust"
)

// recordCodexTrust records Codex's trust for Observer's own entries in
// t.dir/hooks.json, in t.dir/config.toml [hooks.state] (live check
// 2026-10-20: Codex 0.144.4 ran no untrusted hook at all, so the Windows
// Codex tool gate never existed). It runs under the consent that already
// authorized the hook write (init's checklist / batch flags, or
// [observer.hooks] auto_register for `observer start`), right after it.
//
// Only what codextrust.PlanTrust plans is written: Observer-owned handlers,
// hashed exactly as Codex does, never an entry the user turned off in
// /hooks. The edit is surgical (cfgfmt, no re-serialization, so every other
// byte of a file that may hold a credential is kept), verified by
// re-classifying the result before it is written, written atomically with
// the file's mode kept, and idempotent (an entry already trusted with its
// current hash is not touched). There is deliberately NO backup copy:
// config.toml is a credential-bearing file (D-268), which Observer never
// copies; the edit adds only [hooks.state] records, and unregistering
// removes exactly the ones Observer wrote (removeCodexTrust). Non-fatal: the
// hooks stay registered and the reason lands in res.TrustNote (never file
// contents); `observer doctor` and the dashboard report the untrusted
// entries.
func (r *Registry) recordCodexTrust(res *RegistrationResult, t codexHookTarget) {
	if t.trustKey == nil {
		return
	}
	hooksPath := filepath.Join(t.dir, codexHooksFile)
	keyPath, ok := t.trustKey(hooksPath)
	if !ok {
		res.TrustNote = "Codex trust not recorded: the path Codex keys trust with is unknown for " + hooksPath + "; approve Observer's entries in codex /hooks"
		return
	}
	cfgPath := filepath.Join(t.dir, "config.toml")
	unlock, err := r.lockSettings(cfgPath)
	if err != nil {
		res.TrustNote = "Codex trust not recorded: " + safeTrustReason(err)
		return
	}
	defer unlock()
	pinned := pinWriteTarget(cfgPath)

	hooksRaw, err := os.ReadFile(hooksPath)
	if err != nil {
		res.TrustNote = "Codex trust not recorded: hooks.json could not be read"
		return
	}
	cfgRaw, err := os.ReadFile(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.TrustNote = "Codex trust not recorded: config.toml could not be read"
		return
	}
	in := codextrust.TrustInput{KeyPath: keyPath, HooksJSON: hooksRaw, ConfigTOML: cfgRaw, Owned: t.matchMine}
	plan, skipped, err := codextrust.PlanTrust(in)
	if err != nil {
		res.TrustNote = "Codex trust not recorded: " + safeTrustReason(err)
		return
	}
	if len(skipped) > 0 {
		res.TrustNote = "Codex trust not recorded for " + describeTrustSkips(skipped) + "; approve those entries in codex /hooks"
	}
	if len(plan) == 0 {
		return
	}
	doc, err := cfgfmt.ParseWith(cfgfmt.FormatTOML, cfgRaw, cfgfmt.Options{ForbidReserialize: true})
	if err != nil {
		res.TrustNote = "Codex trust not recorded: config.toml could not be parsed for an in-place edit; approve Observer's entries in codex /hooks"
		return
	}
	var events []string
	for _, rec := range plan {
		if err := doc.Set(cfgfmt.Path{"hooks", "state", rec.Key, "trusted_hash"}, rec.Hash); err != nil {
			res.TrustNote = "Codex trust not recorded: config.toml's [hooks.state] cannot be edited in place without rewriting the file; approve Observer's entries in codex /hooks"
			return
		}
		events = append(events, rec.Event)
	}
	out := doc.Bytes()
	if err := verifyCodexTrust(in, out, events); err != nil {
		res.TrustNote = "Codex trust not recorded: " + err.Error()
		return
	}
	if err := atomicWriteFileMode(pinned, out, fileModeOr(pinned.target, 0o600)); err != nil {
		res.TrustNote = "Codex trust not recorded: config.toml could not be written"
		return
	}
	sort.Strings(events)
	res.TrustRecorded = events
}

// verifyCodexTrust re-reads the edited config.toml through the same
// classifier `observer doctor` uses and fails unless every planned event
// now reads as trusted.
func verifyCodexTrust(in codextrust.TrustInput, cfg []byte, events []string) error {
	rep, err := codextrust.Classify(codextrust.Input{
		HooksPath: in.KeyPath, HooksJSON: in.HooksJSON, ConfigTOML: cfg,
		Expected: events, Owned: in.Owned,
	})
	if err != nil {
		return errors.New("the edited config.toml did not parse back")
	}
	trusted := map[string]bool{}
	for _, e := range rep.Entries {
		trusted[e.Event] = e.State == codextrust.StateTrusted
	}
	for _, e := range events {
		if !trusted[e] {
			return errors.New("the edited config.toml did not read back as trusted for " + e)
		}
	}
	return nil
}

// removeCodexTrust removes, after Observer's entries left hooks.json, the
// trust records Observer wrote for them: a [hooks.state] trusted_hash equal
// to the hash of an Observer entry in the pre-removal hooks.json (prior).
// A record the user changed, or one for a user's hook, never matches and
// stays. Non-fatal, like recordCodexTrust.
func (r *Registry) removeCodexTrust(res *UnregistrationResult, dir string, prior []byte, trustKey func(string) (string, bool)) {
	if trustKey == nil || r.opts.DryRun {
		return
	}
	hooksPath := filepath.Join(dir, codexHooksFile)
	keyPath, ok := trustKey(hooksPath)
	if !ok {
		return
	}
	recs, err := codextrust.OwnedTrustRecords(codextrust.TrustInput{KeyPath: keyPath, HooksJSON: prior, Owned: isObserverCodexEntry})
	if err != nil || len(recs) == 0 {
		return
	}
	cfgPath := filepath.Join(dir, "config.toml")
	unlock, err := r.lockSettings(cfgPath)
	if err != nil {
		res.TrustNote = "Codex trust records not removed: " + safeTrustReason(err)
		return
	}
	defer unlock()
	pinned := pinWriteTarget(cfgPath)
	cfgRaw, err := os.ReadFile(cfgPath)
	if err != nil {
		return // no config.toml: nothing recorded
	}
	doc, err := cfgfmt.ParseWith(cfgfmt.FormatTOML, cfgRaw, cfgfmt.Options{ForbidReserialize: true})
	if err != nil {
		res.TrustNote = "Codex trust records not removed: config.toml could not be parsed for an in-place edit"
		return
	}
	// Per record: one that cannot be removed in place is reported and
	// kept, and never stops the others (a failed Delete leaves the
	// document unchanged).
	var removed, kept []string
	for _, rec := range recs {
		entry := cfgfmt.Path{"hooks", "state", rec.Key}
		hashPath := cfgfmt.Path{"hooks", "state", rec.Key, "trusted_hash"}
		got, found, err := doc.Get(hashPath)
		if err != nil || !found || got != rec.Hash {
			continue
		}
		target := hashPath
		if table, _, _ := doc.Get(entry); len(asTable(table)) == 1 {
			target = entry // only our record in it: drop the whole table
		}
		if _, err := doc.Delete(target); err != nil {
			kept = append(kept, rec.Event)
			continue
		}
		removed = append(removed, rec.Event)
	}
	if len(kept) > 0 {
		sort.Strings(kept)
		res.TrustNotRemoved = kept
		res.TrustNote = "Codex trust records not removed for " + strings.Join(kept, ", ") +
			": config.toml cannot be edited in place there without rewriting the file; delete their [hooks.state] tables by hand"
	}
	if len(removed) == 0 {
		return
	}
	if err := atomicWriteFileMode(pinned, doc.Bytes(), fileModeOr(pinned.target, 0o600)); err != nil {
		res.TrustNote = "Codex trust records not removed: config.toml could not be written"
		return
	}
	sort.Strings(removed)
	res.TrustRemoved = removed
}

// asTable returns v as a TOML table, nil when it is not one.
func asTable(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// describeTrustSkips renders PlanTrust's skips as "Event (reason)" pairs.
func describeTrustSkips(skips []codextrust.TrustSkip) string {
	parts := make([]string, 0, len(skips))
	for _, s := range skips {
		parts = append(parts, s.Event+" ("+s.Reason+")")
	}
	return strings.Join(parts, ", ")
}

// safeTrustReason returns an error's message only when Observer composed it
// from paths and names (safeMsgError, the test-write guard); anything else
// could quote config.toml and is withheld.
func safeTrustReason(err error) string {
	var safe *safeMsgError
	if errors.As(err, &safe) {
		return safe.msg
	}
	return "the config file could not be locked or read (detail withheld: config.toml can hold a credential)"
}
