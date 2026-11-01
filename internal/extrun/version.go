package extrun

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// VersionProbe describes how to ask a program for its version.
type VersionProbe struct {
	// Args replace the request's arguments (for example ["--version"]).
	Args []string
	// Pattern finds the version in the output; its first capture group is
	// the version when it has one, else the whole match. nil uses
	// DefaultVersionPattern.
	Pattern *regexp.Regexp
}

// VersionInfo is a parsed version answer.
type VersionInfo struct {
	// Version is the parsed version; empty when none was found.
	Version string
	// Line is the output line the version came from, capped.
	Line string
	// Digest is the binary digest the answer belongs to.
	Digest string
	// Cached is true when the answer came from the per-digest cache.
	Cached bool
}

// DefaultVersionPattern matches a dotted version with an optional leading
// "v" and an optional pre-release or build suffix.
var DefaultVersionPattern = regexp.MustCompile(`\bv?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z][0-9A-Za-z.+-]*)?)`)

// The version-probe defaults applied to a zero cap on the probe request.
const (
	versionProbeWall   = 10 * time.Second
	versionProbeOutput = 64 << 10
	versionLineMax     = 200
)

// ParseVersion finds a version in out. It returns the version and the line
// it came from (capped), or empty strings.
func ParseVersion(out []byte, re *regexp.Regexp) (string, string) {
	if re == nil {
		re = DefaultVersionPattern
	}
	for _, line := range strings.Split(string(out), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v := m[0]
		if len(m) > 1 && m[1] != "" {
			v = m[1]
		}
		line = strings.TrimSpace(line)
		if len(line) > versionLineMax {
			line = line[:versionLineMax]
		}
		return v, line
	}
	return "", ""
}

// ProbeVersion runs req with the probe's arguments and parses a version
// from stdout, then stderr. A parsed answer from a run that exited 0 is
// cached per binary digest and argument list, so a later probe of the same
// bytes starts no process (Result.Outcome is OutcomeCached). A changed
// binary has a new digest and is probed again. Zero caps on req take small
// probe defaults (10 seconds, 64 KiB per stream).
func (r *Runner) ProbeVersion(ctx context.Context, req Request, vp VersionProbe) (VersionInfo, Result) {
	req.Args = append([]string(nil), vp.Args...)
	if req.Limits.Wall == 0 {
		req.Limits.Wall = versionProbeWall
	}
	if req.Limits.StdoutBytes == 0 {
		req.Limits.StdoutBytes = versionProbeOutput
	}
	if req.Limits.StderrBytes == 0 {
		req.Limits.StderrBytes = versionProbeOutput
	}
	p, ok := r.prepare(ctx, req)
	if !ok {
		return VersionInfo{}, p.res
	}
	key := p.res.Digests.Binary + "\x00" + strings.Join(vp.Args, "\x00")
	if vp.Pattern != nil {
		key += "\x00" + vp.Pattern.String()
	}
	r.mu.Lock()
	cached, hit := r.versions[key]
	r.mu.Unlock()
	if hit {
		res := p.res
		res.Outcome = OutcomeCached
		cached.Cached = true
		return cached, res
	}
	res := r.execute(ctx, p)
	v, line := ParseVersion(res.Stdout, vp.Pattern)
	if v == "" {
		v, line = ParseVersion(res.Stderr, vp.Pattern)
	}
	info := VersionInfo{Version: v, Line: line, Digest: res.Digests.Binary}
	if v != "" && res.Outcome == OutcomeOK {
		r.mu.Lock()
		if r.versions == nil {
			r.versions = map[string]VersionInfo{}
		}
		r.versions[key] = info
		r.mu.Unlock()
	}
	return info, res
}
