package dastconsent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/secdast"
)

// Version is bumped when Text changes materially (a new probe, a remote
// target); a record of an older version reads not accepted. Version 2
// (security coverage gaps plan item 1): findings are stored against the
// project on this machine, and runs can start from the dashboard.
const Version = 2

// File is the record's name in the security directory.
const File = "dast-consent.json"

// macDomain separates this record's MAC from every other use of the
// posture key.
const macDomain = "sbo-dast-consent-v1"

// Surfaces are the places that may record the accept: each is an explicit
// action by the developer.
var Surfaces = map[string]bool{"dashboard": true, "cli": true}

// Text is what the developer accepts, on both surfaces.
var Text = fmt.Sprintf("Observer's local DAST checker sends a few plain GET requests to a development server you name "+
	"on this machine (localhost, 127.0.0.1 or ::1 with a port; anything else is refused, also after name resolution, and "+
	"no redirect off that address is followed), at most %d requests and %d seconds per run, and checks what comes back: "+
	"security headers, cookie flags, the CORS answer to a made-up origin, whether /.git/HEAD and /.env are served, "+
	"directory listings, source maps, framework debug pages and version banners. It sends no cookie, password or token, "+
	"submits nothing and changes nothing, but your server will see and log the requests (/.git/HEAD, /.env and a random "+
	"missing page among them). At most %d KB of each response is read, and only facts (a status, a header name, a byte "+
	"count) are kept, stored as findings against the project on this machine (Code security > Findings); nothing leaves this "+
	"machine. Each run starts only when you start it, from the command line or the Code security page.",
	secdast.MaxRequests, int(secdast.RunTimeout.Seconds()), secdast.MaxBodyBytes>>10)

// Consent is the node's record of the accept.
type Consent struct {
	Version    int       `json:"version"`
	AcceptedAt time.Time `json:"accepted_at"`
	// Surface is where it was accepted: "cli" or "dashboard".
	Surface string `json:"surface"`
	// By is the local account the accepting process ran as, when known.
	By string `json:"by,omitempty"`
	// MAC is the record's MAC under the posture key (canonical).
	MAC string `json:"mac,omitempty"`
	// Verified is set only by Read, when the MAC verified, and by Record;
	// it is never read from the file.
	Verified bool `json:"-"`
}

// canonical is the MAC input: every field but the MAC, in a fixed order.
func (c Consent) canonical() []byte {
	var b bytes.Buffer
	b.WriteString(strconv.Itoa(c.Version))
	b.WriteByte('\n')
	b.WriteString(c.AcceptedAt.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(c.Surface))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(c.By))
	return b.Bytes()
}

// Accepted reports whether c is a verified record of the current text given
// on a surface that records consent.
func (c Consent) Accepted() bool {
	return c.Verified && c.Version >= Version && !c.AcceptedAt.IsZero() && Surfaces[c.Surface]
}

// Read reads the record in securityDir and verifies its MAC under key;
// anything missing, unreadable or unverified reads not accepted.
func Read(securityDir string, key []byte) Consent {
	if securityDir == "" {
		return Consent{}
	}
	f, err := os.Open(filepath.Join(securityDir, File))
	if err != nil {
		return Consent{}
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) == 0 || len(b) > 4096 {
		return Consent{}
	}
	var c Consent
	if json.Unmarshal(b, &c) != nil {
		return Consent{}
	}
	c.Verified = len(key) > 0 && guardposture.VerifyRecordMAC(macDomain, c.canonical(), key, c.MAC)
	return c
}

// Record records the accept given on surface by the account by at at,
// signed under key, atomically (0600, the directory 0700).
func Record(securityDir, surface, by string, at time.Time, key []byte) (Consent, error) {
	if securityDir == "" {
		return Consent{}, errors.New("dastconsent.Record: no security directory")
	}
	if !Surfaces[surface] || at.IsZero() {
		return Consent{}, errors.New("dastconsent.Record: an accepting surface and a time are required")
	}
	if len(key) == 0 {
		return Consent{}, errors.New("dastconsent.Record: no signing key")
	}
	if len(by) > 128 {
		by = by[:128]
	}
	c := Consent{Version: Version, AcceptedAt: at.UTC(), Surface: surface, By: by}
	c.MAC = guardposture.RecordMAC(macDomain, c.canonical(), key)
	b, err := json.Marshal(c)
	if err != nil {
		return Consent{}, fmt.Errorf("dastconsent.Record: %w", err)
	}
	if err := os.MkdirAll(securityDir, 0o700); err != nil {
		return Consent{}, fmt.Errorf("dastconsent.Record: %w", err)
	}
	tmp, err := os.CreateTemp(securityDir, ".tmp-dast-consent-*")
	if err != nil {
		return Consent{}, fmt.Errorf("dastconsent.Record: %w", err)
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o600)
	}
	if werr == nil {
		werr = os.Rename(name, filepath.Join(securityDir, File))
	}
	if werr != nil {
		_ = os.Remove(name)
		return Consent{}, fmt.Errorf("dastconsent.Record: %w", werr)
	}
	c.Verified = true
	return c, nil
}
