package secreachsvc

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

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

// srcoptin.go is the ONE owner of the source-mode symbol check's opt-in
// record (plan section 14.5 item 3b, 3b-src; plan 14.13 "Consent and
// R-165"): the developer's per-project word that `observer security scan
// --reach go-source` may run the project's own Go toolchain (go, cgo and the
// C compiler, on project input) under osv-scanner's call analysis. One file
// in the security directory, SourceOptInFile, maps a project root hash to
// one entry; each entry is signed under the node's posture key
// (guardposture.RecordMAC, its own domain, the root hash in the MAC input)
// so a hand-written entry, or one copied to another project, reads not
// opted in. The entry also carries the developer's override of the
// isolation rule (AllowUnisolated): where the isolation component's
// no-network run is not available the check is refused unless this is set,
// or the developer passes the run flag.
//
// Guard rule R-165 denies an agent the verbs that write it, the dashboard
// route and the file (consentRecordPatterns). Node-local: no org row
// builder reads it.

// SourceOptInFile is the record's name in the security directory.
const SourceOptInFile = "reach-go-source-optin.json"

// SourceOptInVersion is bumped when SourceOptInText changes materially; an
// entry of an older version reads not opted in.
const SourceOptInVersion = 1

// sourceOptInDomain separates this record's MAC from every other use of
// the posture key.
const sourceOptInDomain = "sbo-reach-go-source-optin-v1"

// maxSourceOptInBytes and maxSourceOptInProjects cap the file.
const (
	maxSourceOptInBytes    = 1 << 20
	maxSourceOptInProjects = 512
)

// SourceOptInSurfaces are the places that may record the opt-in: each is
// an explicit action by the developer.
var SourceOptInSurfaces = map[string]bool{"cli": true, "dashboard": true}

// SourceOptInText is what the developer opts in to, on both surfaces.
const SourceOptInText = "The Go source check runs osv-scanner's call analysis once per go.mod of this project, which " +
	"runs this machine's Go toolchain on the project's own code: `go list` type-checks every package the module " +
	"builds, and a cgo package runs cgo and the C compiler with the flags its #cgo lines ask for (Go's own cgo flag " +
	"allow-list is the only filter). It runs with GOTOOLCHAIN=local, GOPROXY=off, GOFLAGS=-mod=readonly and " +
	"GOWORK=off, its own HOME, build cache and telemetry directory, inside the isolation component's no-network " +
	"run, and under a memory cap you set (default 12 GiB): on a large module it needs several GB. A module that is " +
	"not already in your module cache is not downloaded, so that go.mod reads \"not checked\". It runs only when " +
	"you start it. Results label findings called or not called for that go.mod; nothing is closed or hidden, and " +
	"nothing leaves this machine."

// SourceOptIn is one project's entry.
type SourceOptIn struct {
	Version  int       `json:"version"`
	OptedAt  time.Time `json:"opted_at"`
	Surface  string    `json:"surface"`
	By       string    `json:"by,omitempty"`
	RootHash string    `json:"-"`
	// AllowUnisolated is the developer's override: run without the
	// isolation component where it is not available.
	AllowUnisolated bool   `json:"allow_unisolated,omitempty"`
	MAC             string `json:"mac,omitempty"`
	// Verified is set only by ReadSourceOptIn when the MAC verified, and
	// by RecordSourceOptIn; never read from the file.
	Verified bool `json:"-"`
}

// canonical is the MAC input: the root hash and every field but the MAC.
func (o SourceOptIn) canonical() []byte {
	var b bytes.Buffer
	b.WriteString(o.RootHash)
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(o.Version))
	b.WriteByte('\n')
	b.WriteString(o.OptedAt.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(o.Surface))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(o.By))
	b.WriteByte('\n')
	b.WriteString(strconv.FormatBool(o.AllowUnisolated))
	return b.Bytes()
}

// OptedIn reports whether o is a verified entry of the current text given
// on a surface that records the opt-in.
func (o SourceOptIn) OptedIn() bool {
	return o.Verified && o.Version >= SourceOptInVersion && !o.OptedAt.IsZero() && SourceOptInSurfaces[o.Surface]
}

// UnisolatedAllowed reports a verified opt-in whose developer allowed the
// run without isolation.
func (o SourceOptIn) UnisolatedAllowed() bool { return o.OptedIn() && o.AllowUnisolated }

func sourceOptInPath(dir string) string { return filepath.Join(dir, SourceOptInFile) }

func readSourceOptIns(dir string) map[string]SourceOptIn {
	out := map[string]SourceOptIn{}
	if dir == "" {
		return out
	}
	f, err := os.Open(sourceOptInPath(dir)) //nolint:gosec // G304: the record's own file in the security directory
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSourceOptInBytes+1))
	if err != nil || len(b) > maxSourceOptInBytes {
		return out
	}
	var raw map[string]SourceOptIn
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	for k, v := range raw {
		if validRootHash(k) {
			v.RootHash = k
			out[k] = v
		}
	}
	return out
}

// ReadSourceOptIn returns the project's entry, its MAC checked under key;
// anything missing, unreadable or unverified reads not opted in.
func ReadSourceOptIn(dir, rootHash string, key []byte) SourceOptIn {
	o, ok := readSourceOptIns(dir)[rootHash]
	if !ok {
		return SourceOptIn{}
	}
	o.Verified = len(key) > 0 && guardposture.VerifyRecordMAC(sourceOptInDomain, o.canonical(), key, o.MAC)
	return o
}

// RecordSourceOptIn records the project's opt-in given on surface by the
// account by at at, with the isolation override, signed under key.
func RecordSourceOptIn(dir, rootHash, surface, by string, allowUnisolated bool, at time.Time, key []byte) (SourceOptIn, error) {
	switch {
	case dir == "":
		return SourceOptIn{}, errors.New("secreachsvc.RecordSourceOptIn: no security directory")
	case !validRootHash(rootHash):
		return SourceOptIn{}, errors.New("secreachsvc.RecordSourceOptIn: no project")
	case !SourceOptInSurfaces[surface] || at.IsZero():
		return SourceOptIn{}, errors.New("secreachsvc.RecordSourceOptIn: an opting surface and a time are required")
	case len(key) == 0:
		return SourceOptIn{}, errors.New("secreachsvc.RecordSourceOptIn: no signing key")
	}
	if len(by) > 128 {
		by = by[:128]
	}
	o := SourceOptIn{Version: SourceOptInVersion, OptedAt: at.UTC(), Surface: surface, By: by, RootHash: rootHash, AllowUnisolated: allowUnisolated}
	o.MAC = guardposture.RecordMAC(sourceOptInDomain, o.canonical(), key)
	all := readSourceOptIns(dir)
	if _, known := all[rootHash]; !known && len(all) >= maxSourceOptInProjects {
		return SourceOptIn{}, errors.New("secreachsvc.RecordSourceOptIn: too many projects opted in")
	}
	all[rootHash] = o
	if err := writeSourceOptIns(dir, all); err != nil {
		return SourceOptIn{}, err
	}
	o.Verified = true
	return o, nil
}

// WithdrawSourceOptIn removes the project's entry; withdrawing one that is
// not there is no error.
func WithdrawSourceOptIn(dir, rootHash string) error {
	all := readSourceOptIns(dir)
	if _, ok := all[rootHash]; !ok {
		return nil
	}
	delete(all, rootHash)
	if len(all) == 0 {
		if err := os.Remove(sourceOptInPath(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("secreachsvc.WithdrawSourceOptIn: %w", err)
		}
		return nil
	}
	return writeSourceOptIns(dir, all)
}

func writeSourceOptIns(dir string, all map[string]SourceOptIn) error {
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return fmt.Errorf("secreachsvc: source opt-in: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secreachsvc: source opt-in: %w", err)
	}
	if err := fsatomic.WriteFile(sourceOptInPath(dir), append(b, '\n'), fsatomic.Options{TempPattern: ".reach-optin-*"}); err != nil {
		return fmt.Errorf("secreachsvc: source opt-in: %w", err)
	}
	return nil
}
