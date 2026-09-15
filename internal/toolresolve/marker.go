package toolresolve

import (
	"errors"
	"fmt"
	"strings"
)

// PathMarkBegin and PathMarkEnd delimit the captured $PATH in a login-shell
// capture. The capture wraps the value in a marker PAIR because a login shell
// prints rc-file banners (motd, version-manager chatter, "Welcome to …") on
// stdout that would otherwise be absorbed into the PATH list. The constants
// live in the pure package so the marker PARSER is table-testable without a
// subprocess; the per-shell argv table that emits them lives in
// internal/toolresolve/host (this package may not import os/exec).
const (
	PathMarkBegin = "__SB_PATH_BEGIN__"
	PathMarkEnd   = "__SB_PATH_END__"
)

// ErrNoPathMarkers reports that the captured output did not carry exactly one
// well-formed marker pair. The caller treats it as "this capture attempt did
// not work" and either tries the next attempt or proceeds on the process PATH
// alone — never as a fatal error.
var ErrNoPathMarkers = errors.New("toolresolve: login capture carried no well-formed PATH marker pair")

// ParsePathMarkers extracts the PATH entries a login-shell capture printed
// between PathMarkBegin and PathMarkEnd. Banner text before and after the pair
// is tolerated and discarded. The value between the markers is a POSIX shell's
// $PATH, so it is split on ':' (NOT filepath.SplitList, whose separator follows
// the TEST host rather than the captured shell); empty entries are dropped.
// A missing marker, a duplicated marker, or an end marker preceding the begin
// marker returns ErrNoPathMarkers — the capture is discarded rather than
// half-trusted. An empty PATH between well-formed markers is not an error: it
// returns nil dirs and a nil error.
func ParsePathMarkers(out string) ([]string, error) {
	begin := strings.Count(out, PathMarkBegin)
	end := strings.Count(out, PathMarkEnd)
	if begin != 1 || end != 1 {
		return nil, fmt.Errorf("%w (begin=%d end=%d)", ErrNoPathMarkers, begin, end)
	}
	i := strings.Index(out, PathMarkBegin)
	j := strings.Index(out, PathMarkEnd)
	if j < i {
		return nil, fmt.Errorf("%w (end marker precedes begin marker)", ErrNoPathMarkers)
	}
	raw := out[i+len(PathMarkBegin) : j]
	var dirs []string
	for _, d := range strings.Split(raw, ":") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		dirs = append(dirs, d)
	}
	return dirs, nil
}
