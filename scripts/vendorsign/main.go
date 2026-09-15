package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// usage is printed for a missing or unknown verb. It is deliberately
// short: the operator-facing explanation lives in doc.go and in the
// README beside the private key, not in three screens of flag help.
const usage = `usage:
  vendorsign keygen         -out DIR
  vendorsign sign           -key FILE ARCHIVE...
  vendorsign manifest       -key FILE -dir DIR -version vX.Y.Z -channel stable -out FILE
  vendorsign schema-version`

// run dispatches a verb. Split from main so the whole tool is testable
// without a subprocess.
func run(args []string, out *os.File) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:], out)
	case "sign":
		return runSign(args[1:], out)
	case "manifest":
		return runManifest(args[1:], out)
	case "schema-version":
		return runSchemaVersion(out)
	case "-h", "--help", "help":
		fmt.Fprintln(out, usage)
		return nil
	default:
		return fmt.Errorf("vendorsign: unknown verb %q\n%s", args[0], usage)
	}
}

// runSchemaVersion prints the agent DB schema high-water mark and NOTHING
// else. The release pipeline substitutes it straight into
// `manifest -schema-version`, so a line of prose here would become a flag
// parse error there.
func runSchemaVersion(out *os.File) error {
	v, err := agentSchemaVersion()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, v)
	return nil
}

// runKeygen mints a new vendor keypair.
func runKeygen(args []string, out *os.File) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	dir := fs.String("out", "", "directory to write the private key into (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("vendorsign keygen: -out is required")
	}
	pub, path, err := generateKeypair(*dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "private key: %s (mode 0600)\n", path)
	fmt.Fprintf(out, "public key : %s\n", pub)
	fmt.Fprintf(out, "key id     : %s\n", keyIDFromB64(pub))
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Next: put the PUBLIC key in internal/update/vendorkey.go (moving the current")
	fmt.Fprintln(out, "VendorPublicKeyV1 into VendorPublicKeyV0Previous), ship one release with both")
	fmt.Fprintln(out, "accepted, and only then swap the OBSERVER_VENDOR_SIGNING_KEY secret.")
	return nil
}

// keyIDFromB64 renders the key id for a base64 public key, or a
// placeholder when it does not parse. Used for operator output only.
func keyIDFromB64(b64 string) string {
	pub, err := parsePublicKey(b64)
	if err != nil {
		return "(unparseable)"
	}
	return keyID(pub)
}

// runSign signs each archive named on the command line.
func runSign(args []string, out *os.File) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "path to the Ed25519 signing key (required)")
	allowUnpinned := fs.Bool("allow-unpinned-key", false,
		"sign with a key this tree's agents do NOT accept (a deliberate rotation step)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("vendorsign sign: -key is required")
	}
	if fs.NArg() == 0 {
		return errors.New("vendorsign sign: name at least one archive")
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
		fmt.Fprintln(out, warn)
	}
	for _, archive := range fs.Args() {
		sigPath, serr := signArchive(archive, priv)
		if serr != nil {
			return serr
		}
		fmt.Fprintf(out, "signed %s -> %s\n", filepath.Base(archive), filepath.Base(sigPath))
	}
	return nil
}

// runManifest builds and signs the release manifest for one channel.
func runManifest(args []string, out *os.File) error {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	keyPath := fs.String("key", "", "path to the Ed25519 signing key (required)")
	dir := fs.String("dir", ".", "directory holding the release assets")
	version := fs.String("version", "", "release version, e.g. v1.33.0 (required)")
	channel := fs.String("channel", "stable", "stable | lts | edge")
	outPath := fs.String("out", "", "output path (default: <dir>/update-manifest-<channel>.json)")
	notes := fs.String("notes", "", "plain-text release note (<= 280 runes)")
	notesURL := fs.String("notes-url", "", "https link to the release notes")
	minFrom := fs.String("min-from-version", "", "oldest installed version that may jump straight here")
	minServer := fs.String("min-server-version", "", "org-server version this agent version needs")
	expiresDays := fs.Int("expires-days", defaultExpiryDays, "manifest freshness window in days")
	manifestVersion := fs.Int64("manifest-version", 0, "publish ordinal (default: the release timestamp in unix seconds)")
	schemaVersion := fs.Int("schema-version", 0,
		"agent DB schema version this release carries (0 = unknown; nodes then snapshot on every apply)")
	allowUnpinned := fs.Bool("allow-unpinned-key", false,
		"sign with a key this tree's agents do NOT accept (a deliberate rotation step)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("vendorsign manifest: -key is required")
	}
	if *version == "" {
		return errors.New("vendorsign manifest: -version is required")
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
		fmt.Fprintln(out, warn)
	}
	env, m, err := buildManifest(BuildOptions{
		Dir: *dir, Version: *version, Channel: *channel,
		ManifestVersion: *manifestVersion, ReleasedAt: time.Now(),
		ExpiresDays: *expiresDays, Notes: *notes, NotesURL: *notesURL,
		MinFromVersion: *minFrom, MinServerVersion: *minServer,
		SchemaVersion: *schemaVersion,
		Key:           priv,
	})
	if err != nil {
		return err
	}
	target := *outPath
	if target == "" {
		target = filepath.Join(*dir, fmt.Sprintf("update-manifest-%s.json", *channel))
	}
	if err := writeEnvelope(target, env); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", target)
	fmt.Fprintf(out, "  channel          %s\n", m.Channel)
	fmt.Fprintf(out, "  version          %s\n", m.Version)
	fmt.Fprintf(out, "  manifest_version %d\n", m.ManifestVersion)
	fmt.Fprintf(out, "  expires_at       %s\n", m.ExpiresAt)
	fmt.Fprintf(out, "  key_id           %s\n", env.KeyID)
	for _, a := range m.Artifacts {
		fmt.Fprintf(out, "  %-10s %-8s %s (%d bytes)\n", a.OS, a.Arch, a.Filename, a.SizeBytes)
	}
	return nil
}
