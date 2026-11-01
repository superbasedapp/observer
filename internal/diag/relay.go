package diag

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
	"github.com/marmutapp/superbased-observer/internal/routeattest"
	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

// relay.go: the doctor rows of the fail-open Windows route relay (surface-gap
// finding CC-9, decision D12; internal/winrelay). Two rows, on a Windows host
// or inside WSL only:
//
//   - relay.live_gate: the relay and the Windows route change are built and
//     switched off until live checks LC6 and LC14 pass (DEC-12).
//   - relay.bypass: the relay's bypass journal. Every fail-open forward the
//     relay made inside routeattest.ObservedWindow is a WARN: those requests
//     skipped Observer's proxy, and the sessions they belong to read as
//     unproxied in the route gate (decision D11). An unreadable journal is a
//     WARN too, since a bypass that cannot be read cannot be judged.

const (
	relayGateCheckName   = "relay.live_gate"
	relayBypassCheckName = "relay.bypass"
	// maxRelayJournalBytes caps one journal generation read; the relay
	// rotates at winrelay.DefaultJournalMaxBytes.
	maxRelayJournalBytes = 4 * winrelay.DefaultJournalMaxBytes
)

// RelayOwnHome is the home the relay on this host writes its journal under,
// and the home a reader on the same host reads: the account's real home,
// read through the pinned-home rule (crossmount.HomeEnv with nothing pinned:
// USERPROFILE on Windows, HOME elsewhere). An isolated process (HOME
// redirected, --no-crossmount, a config outside the real home) gets no
// home, so `observer relay serve` refuses to start rather than record
// bypasses where no reader looks. Writer and readers both call this one
// function and winrelay.JournalDirUnder.
func RelayOwnHome() (string, error) {
	return relayOwnHomeFrom(runtime.GOOS, crossmount.HomeEnv("", nil))
}

// relayOwnHomeFrom is RelayOwnHome over an injected OS and lookup.
func relayOwnHomeFrom(goos string, getenv func(string) string) (string, error) {
	name := "HOME"
	if goos == "windows" {
		name = "USERPROFILE"
	}
	home := getenv(name)
	if home == "" || !relayAbs(goos, home) {
		return "", fmt.Errorf("diag.RelayOwnHome: no real account home (%s is unset, relative, or this process's home is isolated)", name)
	}
	return home, nil
}

// relayAbs reports whether home is absolute in goos's spelling.
func relayAbs(goos, home string) bool {
	if goos == "windows" {
		return len(home) >= 3 && home[1] == ':' && (home[2] == '\\' || home[2] == '/')
	}
	return filepath.IsAbs(home)
}

// RelayJournalDirs lists the directories holding the relay's bypass journal
// that this node reads (winrelay.JournalDirUnder of each home): on a
// Windows host its own home (ownHome, from RelayOwnHome; "" reads none);
// inside WSL each Windows home proven the current Windows user's (the
// relay runs on that host). Nil elsewhere, and nil inside WSL when no home
// is proven the user's (another user's journal is never read). owned is the
// crossmount ownership seam.
func RelayJournalDirs(goos, ownHome string, isWSL bool, homes []crossmount.HomeRoot, owned func(string) bool) []string {
	if goos == "windows" {
		if ownHome == "" {
			return nil
		}
		return []string{winrelay.JournalDirUnder(ownHome)}
	}
	if !isWSL || owned == nil {
		return nil
	}
	var out []string
	for _, h := range homes {
		if h.OS == crossmount.OSWindows && owned(h.Path) {
			out = append(out, winrelay.JournalDirUnder(h.Path))
		}
	}
	return out
}

// RelayJournal is the bypass journal read from a set of directories.
type RelayJournal struct {
	// Found: at least one journal file exists.
	Found bool
	// Summary is the recorded bypasses inside the window.
	Summary winrelay.Summary
	// Unreadable lists journal files that exist but could not be read.
	Unreadable []string
}

// ReadRelayJournal reads both journal generations in each directory through
// the bounded regular-file reader and summarizes the records at or after
// since.
func ReadRelayJournal(dirs []string, since time.Time) RelayJournal {
	var out RelayJournal
	var entries []winrelay.Entry
	skipped := 0
	for _, dir := range dirs {
		for _, name := range []string{winrelay.JournalRotated, winrelay.JournalFile} {
			path := filepath.Join(dir, name)
			data, err := regularfile.Read(path, maxRelayJournalBytes)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			out.Found = true
			if err != nil {
				out.Unreadable = append(out.Unreadable, path)
				continue
			}
			e, s := winrelay.ParseJournal(data)
			entries = append(entries, e...)
			skipped += s
		}
	}
	out.Summary = winrelay.Summarize(entries, since, skipped)
	return out
}

// RelayBypassSince reads this node's relay journal for the records at or
// after since (production wiring of RelayJournalDirs + ReadRelayJournal).
// homeOverride is the caller's pinned home ("" for none): a pinned or
// isolated home reads no foreign home (crossmount.AutoDetectSuppressed).
func RelayBypassSince(homeOverride string, since time.Time) RelayJournal {
	isWSL := crossmount.IsWSL()
	var homes []crossmount.HomeRoot
	if isWSL && !crossmount.AutoDetectSuppressed(homeOverride, "") {
		homes = crossmount.AllHomes()
	}
	own := ""
	if runtime.GOOS == "windows" {
		own, _ = RelayOwnHome()
	}
	dirs := RelayJournalDirs(runtime.GOOS, own, isWSL, homes, crossmount.HomeOwnedByCurrentWindowsUser)
	return ReadRelayJournal(dirs, since)
}

// checkRelay is the production entry point of the relay rows.
func checkRelay(homeOverride string, now time.Time) []Check {
	if runtime.GOOS != "windows" && !crossmount.IsWSL() {
		return nil
	}
	return relayChecks(runtime.GOOS, crossmount.IsWSL(), RelayBypassSince(homeOverride, now.Add(-routeattest.ObservedWindow)))
}

// relayChecks builds the relay rows from already read facts.
func relayChecks(goos string, isWSL bool, j RelayJournal) []Check {
	if goos != "windows" && !isWSL {
		return nil
	}
	var out []Check
	if g := winrelay.Gate(); g.Waiting() {
		out = append(out, Check{
			Name: relayGateCheckName, Status: StatusOK,
			Message: "the fail-open Windows route relay is " + g.Text() + "; Windows routes keep their WSL proxy target and `observer relay serve` refuses to start until then",
		})
	}
	if !j.Found {
		return out
	}
	days := int(routeattest.ObservedWindow / (24 * time.Hour))
	c := Check{Name: relayBypassCheckName, Status: StatusOK, Message: fmt.Sprintf("no request bypassed Observer's proxy through the relay in the last %dd", days)}
	for _, p := range j.Unreadable {
		c.Status = StatusWarn
		c.Details = append(c.Details, "bypass journal unreadable: "+p+" (its bypasses cannot be judged)")
	}
	if n := j.Summary.Total(); n > 0 {
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("%d request(s) bypassed Observer's proxy through the relay in the last %dd (the proxy was unreachable, so the relay forwarded them straight to the provider); their sessions read as unproxied in the route gate", n, days)
		for _, t := range j.Summary.Tools {
			c.Details = append(c.Details, fmt.Sprintf("%s: %d bypass(es), %s to %s", t.Tool, t.Count,
				t.First.UTC().Format(time.RFC3339), t.Last.UTC().Format(time.RFC3339)))
		}
	} else if len(j.Unreadable) > 0 {
		c.Message = "the relay's bypass journal could not be read"
	}
	if j.Summary.Skipped > 0 {
		c.Details = append(c.Details, fmt.Sprintf("%d journal line(s) could not be decoded", j.Summary.Skipped))
	}
	return append(out, c)
}
