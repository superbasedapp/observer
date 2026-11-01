//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_opengrep_pack.go is the rule pack's file side (security pillar
// plan section 8.5, Phase G lane G1): the embedded floor, a newer pack
// installed through the signed content channel (content kind
// security.rule_pack, internal/contentchan), and the choice between them
// (secrulepack.Choose: the newer verified pack wins). Nothing here reaches
// the network: a pack arrives only as files an operator imports.

// codeRulesContentDir is the content root of the code rules, under the
// security directory: separate from the install gate's root, so the two
// components never share a kind directory.
const codeRulesContentDir = "code-content"

// codeRulesStore is the content store for a resolved config path.
func codeRulesStore(resolvedConfig string) contentchan.Store {
	return contentchan.Store{Root: filepath.Join(secposture.LayoutFor(resolvedConfig).Dir, codeRulesContentDir)}
}

// codeRulesTrust is the key material a rule pack verifies with: the vendor
// key compiled into this binary (a variable so tests can stand in a key).
var codeRulesTrust = func() contentchan.Trust { return contentchan.Trust{VendorKeys: codeVendorKeys()} }

// codePack is the pack in use and where it came from.
type codePack struct {
	Pack   *secrulepack.Pack
	Source secrulepack.Source
	// Freshness is the imported pack's freshness ("" for the floor).
	Freshness content.Freshness
	// Note is one plain sentence when an installed pack was not used (it
	// failed to re-verify, it is past its age floor, or it is not newer).
	Note string
}

// loadCodePack returns the pack to use. An installed pack is re-verified
// on every load (signature, ordering, the bundle's digest); one that fails,
// or is past the kind's age floor, is set aside with a note and the floor
// is used.
func loadCodePack(store contentchan.Store, tr contentchan.Trust) (codePack, error) {
	floor, err := secrulepack.Floor()
	if err != nil {
		return codePack{}, fmt.Errorf("the embedded rule pack does not validate: %w", err)
	}
	out := codePack{Pack: floor, Source: secrulepack.SourceFloor}
	l, err := store.Load(content.RulePack, tr, 0)
	switch {
	case errors.Is(err, contentchan.ErrNotInstalled):
		return out, nil
	case err != nil:
		out.Note = "an installed rule pack failed to re-verify (" + string(content.ReasonOf(err)) + "); the embedded pack is used"
		return out, nil
	case l.Freshness == content.Unknown:
		out.Note = "the installed rule pack is past its age floor; the embedded pack is used"
		return out, nil
	}
	raw, err := l.ReadArtifact(secrulepack.BundleName)
	if err != nil {
		out.Note = "the installed rule pack's bundle failed its digest check; the embedded pack is used"
		return out, nil
	}
	imported, err := secrulepack.DecodeBundle(raw)
	if err != nil {
		out.Note = "the installed rule pack does not validate; the embedded pack is used"
		return out, nil
	}
	out.Pack, out.Source = secrulepack.Choose(floor, imported)
	if out.Source == secrulepack.SourceImported {
		out.Freshness = l.Freshness
	} else {
		out.Note = "the installed rule pack " + imported.Version() + " is not newer than the embedded " + floor.Version() + "; the embedded pack is used"
	}
	return out, nil
}

// importCodePack installs the rule pack found under src, laid out as a
// content kind directory: src/security.rule_pack/manifest.json (the signed
// envelope) beside the bundle. The bundle is validated as a pack before
// the channel installs it, so a pack that would be set aside at load is
// refused at import.
func importCodePack(src string, dst contentchan.Store, tr contentchan.Trust) (*secrulepack.Pack, error) {
	dir := filepath.Join(src, string(content.RulePack))
	env, err := readCappedFile(filepath.Join(dir, contentchan.ManifestFile), content.MaxEnvelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("no signed rule pack under %s: %w", src, err)
	}
	raw, err := readCappedFile(filepath.Join(dir, secrulepack.BundleName), secrulepack.MaxBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("the rule pack bundle: %w", err)
	}
	p, err := secrulepack.DecodeBundle(raw)
	if err != nil {
		return nil, err
	}
	if _, err := dst.Install(content.RulePack, env, map[string][]byte{secrulepack.BundleName: raw}, tr); err != nil {
		return nil, err
	}
	return p, nil
}

// readCappedFile reads a regular file of at most limit bytes.
func readCappedFile(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s is over its %d byte cap", path, limit)
	}
	return os.ReadFile(path)
}
