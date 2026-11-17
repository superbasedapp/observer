package secdast

import (
	"encoding/json"
	"strconv"
)

// MaxLaunchJSON is the most bytes of a .claude/launch.json read.
const MaxLaunchJSON = 256 << 10

// Candidate is one dev server URL the developer may pick (section 14.9:
// candidates come from .claude/launch.json ports, never a remote host).
type Candidate struct {
	URL string `json:"url"`
	// Name is the launch configuration's name, or the dev server the
	// project's files suggest ("npm run dev (vite)").
	Name string `json:"name,omitempty"`
	// Source is the file kind that named it (SourceLaunchJSON, ...).
	Source string `json:"source,omitempty"`
	// Listening is "yes" when the kernel's own socket table shows a
	// listening socket on the port (ListeningPorts), "no" when it shows
	// none, "" when the operating system exposes no such table (unknown).
	Listening string `json:"listening,omitempty"`
}

// launchFile is the part of .claude/launch.json read: each configuration's
// name, port and optional url.
type launchFile struct {
	Configurations []struct {
		Name string          `json:"name"`
		Port json.RawMessage `json:"port"`
		URL  string          `json:"url"`
	} `json:"configurations"`
}

// LaunchCandidates reads .claude/launch.json bytes: a configuration's url
// when it is a loopback URL with a port (ParseTarget), else
// http://localhost:<port>/. Anything malformed is skipped; nothing is
// resolved or dialed here.
func LaunchCandidates(data []byte) []Candidate {
	if len(data) == 0 || len(data) > MaxLaunchJSON {
		return nil
	}
	var lf launchFile
	if json.Unmarshal(data, &lf) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []Candidate
	add := func(u, name string) {
		t, err := ParseTarget(u)
		if err != nil || seen[t.String()] {
			return
		}
		seen[t.String()] = true
		out = append(out, Candidate{URL: t.String(), Name: clip(name, 80)})
	}
	for _, c := range lf.Configurations {
		if c.URL != "" {
			add(c.URL, c.Name)
			continue
		}
		if p, ok := launchPort(c.Port); ok {
			add("http://localhost:"+strconv.Itoa(p)+"/", c.Name)
		}
	}
	return out
}

// launchPort accepts a JSON number or a numeric string.
func launchPort(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int
	if json.Unmarshal(raw, &n) != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return 0, false
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		n = v
	}
	return n, n >= 1 && n <= 65535
}
