package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// engine.go is the sign step of the security.engine manifest (WINFIX4
// audit finding 6): it assembles the unsigned Opengrep entries that
// `secengine verify` printed into one manifest and signs it, and it
// refuses a manifest missing any release platform
// (secengine.CheckReleaseSet), unless -revocation says it withdraws
// digests. A one-platform manifest otherwise reached every node.
//
//	vendorsign engine -key FILE -out DIR -manifest-version N
//	                  [-epoch 1] [-valid-days 90] [-revocation]
//	                  [-revoke SHA256]... ENTRY.json...

// engineOptions is one engine manifest build.
type engineOptions struct {
	Entries         []string
	Out             string
	ManifestVersion int64
	Epoch           int64
	Issued          time.Time
	Validity        time.Duration
	Revoked         []content.Revocation
	Revocation      bool
	Key             ed25519.PrivateKey
}

func runEngine(args []string, out *os.File) error {
	fsx := flag.NewFlagSet("engine", flag.ContinueOnError)
	keyPath := fsx.String("key", "", "vendor signing key file")
	outDir := fsx.String("out", "", "output directory")
	version := fsx.Int64("manifest-version", 0, "monotonic manifest version")
	epoch := fsx.Int64("epoch", 1, "data epoch")
	days := fsx.Int("valid-days", 90, "validity in days")
	revocation := fsx.Bool("revocation", false, "the manifest withdraws digests (exempt from the every-platform rule; needs -revoke)")
	allowUnpinned := fsx.Bool("allow-unpinned-key", false, "sign with a key this tree's agents do not accept (rotation step 4 only)")
	var revoked revokeFlags
	fsx.Var(&revoked, "revoke", "a sha256 digest the manifest revokes (repeatable)")
	if err := fsx.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *outDir == "" || *version <= 0 || fsx.NArg() == 0 {
		return errors.New("vendorsign engine: -key, -out, a positive -manifest-version and at least one entry file are required")
	}
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	warn, err := checkKeyIsPinned(priv, *allowUnpinned)
	if err != nil {
		return err
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}
	rev := make([]content.Revocation, 0, len(revoked))
	for _, sha := range revoked {
		rev = append(rev, content.Revocation{SHA256: sha})
	}
	m, err := buildEngineManifest(engineOptions{
		Entries: fsx.Args(), Out: *outDir, ManifestVersion: *version, Epoch: *epoch,
		Issued: time.Now().UTC(), Validity: time.Duration(*days) * 24 * time.Hour,
		Revoked: rev, Revocation: *revocation, Key: priv,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "engine: manifest version %d, %d entries, %d revoked\n", m.ManifestVersion, len(m.Entries), len(m.Revoked))
	return nil
}

// buildEngineManifest builds, gates, signs and writes the manifest.
func buildEngineManifest(o engineOptions) (content.Manifest, error) {
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.Engine, ManifestVersion: o.ManifestVersion, Epoch: o.Epoch,
		IssuedAt: o.Issued.Format(time.RFC3339), ExpiresAt: o.Issued.Add(o.Validity).Format(time.RFC3339),
		Revoked: o.Revoked,
	}
	for _, p := range o.Entries {
		b, err := os.ReadFile(p) //nolint:gosec // G304: the operator names the entry files
		if err != nil {
			return content.Manifest{}, fmt.Errorf("vendorsign engine: %w", err)
		}
		var e content.Entry
		if err := json.Unmarshal(b, &e); err != nil {
			return content.Manifest{}, fmt.Errorf("vendorsign engine: %s: %w", p, err)
		}
		m.Entries = append(m.Entries, e)
	}
	content.SortEntries(m.Entries)
	// The gate runs before any signature exists.
	if err := secengine.CheckReleaseSet(m, o.Revocation); err != nil {
		return content.Manifest{}, fmt.Errorf("vendorsign engine: refusing to sign: %w", err)
	}
	if _, err := secengine.FromManifest(m); err != nil {
		return content.Manifest{}, fmt.Errorf("vendorsign engine: refusing to sign: %w", err)
	}
	env, err := content.Sign(m, o.Key)
	if err != nil {
		return content.Manifest{}, fmt.Errorf("vendorsign engine: %w", err)
	}
	b, err := content.EncodeEnvelope(env)
	if err != nil {
		return content.Manifest{}, err
	}
	dir := filepath.Join(o.Out, string(content.Engine))
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: public feed artifacts
		return content.Manifest{}, fmt.Errorf("vendorsign engine: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644); err != nil { //nolint:gosec // public feed artifacts
		return content.Manifest{}, fmt.Errorf("vendorsign engine: %w", err)
	}
	return m, nil
}
