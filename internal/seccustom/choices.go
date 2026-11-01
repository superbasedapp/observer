package seccustom

import (
	"errors"
	"fmt"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// Choices are the import pickers (D-571: no free text for a known option
// set). The file supplies the defaults; a zero field keeps the file's
// value; a set field must come from its closed set, which Apply checks.
type Choices struct {
	// Executable must be one of the discovered candidates.
	Executable string `json:"executable,omitempty"`
	// Companions are chosen per declared companion, in order, each from
	// that companion's candidates; "" keeps the file's path.
	Companions []string `json:"companions,omitempty"`
	Input      Input    `json:"input,omitempty"`
	Output     Output   `json:"output,omitempty"`
	// Limits holds the chosen steps; a zero field keeps the file's.
	Limits Limits `json:"limits,omitempty"`
	Cache  Cache  `json:"cache,omitempty"`
	// NetworkNone turns a declared host list off (the picker offers the
	// declared hosts or none; it never adds a host).
	NetworkNone bool   `json:"network_none,omitempty"`
	Category    string `json:"category,omitempty"`
	// Severity re-maps a level the file names to another severity.
	Severity map[string]secfinding.Severity `json:"severity,omitempty"`
}

// Candidates are what discovery found, per picker that takes a path.
type Candidates struct {
	Executable []string
	// Companions has one list per declared companion.
	Companions [][]string
}

// Apply returns m with the choices applied and validated. A path choice
// outside its candidates, a step outside its picker, or a severity for a
// level the file does not name is refused.
func Apply(m Manifest, c Choices, cand Candidates, opt Options) (Manifest, error) {
	out := m
	out.Argv = append([]string(nil), m.Argv...)
	out.Companions = append([]Companion(nil), m.Companions...)
	out.Severity.Levels = map[string]secfinding.Severity{}
	for k, v := range m.Severity.Levels {
		out.Severity.Levels[k] = v
	}
	switch {
	case c.Executable != "":
		if !slices.Contains(cand.Executable, c.Executable) {
			return Manifest{}, errors.New("the executable must be one Observer discovered")
		}
		if c.Executable != m.Executable {
			out.ExecutableSHA256 = ""
		}
		out.Executable = c.Executable
	case !slices.Contains(cand.Executable, m.Executable):
		return Manifest{}, errors.New("the manifest's executable is not one Observer discovered; pick one")
	}
	if len(c.Companions) > len(out.Companions) {
		return Manifest{}, errors.New("more companion choices than declared companions")
	}
	for i := range out.Companions {
		var list []string
		if i < len(cand.Companions) {
			list = cand.Companions[i]
		}
		pick := out.Companions[i].Path
		if i < len(c.Companions) && c.Companions[i] != "" {
			pick = c.Companions[i]
		}
		if !slices.Contains(list, pick) {
			return Manifest{}, fmt.Errorf("companion %d must be one Observer discovered", i+1)
		}
		if pick != out.Companions[i].Path {
			out.Companions[i].SHA256 = ""
		}
		out.Companions[i].Path = pick
	}
	if c.Input != "" {
		out.Input = c.Input
	}
	if c.Output != "" {
		out.Output = c.Output
	}
	for _, f := range LimitFields() {
		if v := c.Limits.value(f); v != 0 {
			out.Limits = out.Limits.with(f, v)
		}
	}
	if c.Cache != "" {
		out.Cache = c.Cache
	}
	if c.NetworkNone {
		out.Network = Network{Mode: NetworkNone}
	}
	if c.Category != "" {
		out.Category = c.Category
	}
	for k, v := range c.Severity {
		if _, ok := m.Severity.Levels[k]; !ok {
			return Manifest{}, fmt.Errorf("the severity map has no level %q", clip(k, 40))
		}
		out.Severity.Levels[k] = v
	}
	if err := out.Validate(opt); err != nil {
		return Manifest{}, err
	}
	return out, nil
}

// with returns l with one picker set.
func (l Limits) with(f LimitField, v int) Limits {
	switch f {
	case LimitWall:
		l.WallSeconds = v
	case LimitMemory:
		l.MemoryMiB = v
	case LimitCPU:
		l.CPUSeconds = v
	case LimitOutput:
		l.OutputMiB = v
	case LimitChildren:
		l.ChildProcesses = v
	case LimitFile:
		l.FileMiB = v
	}
	return l
}

// FromTemplate returns a template's manifest with the chosen executable
// and companion paths filled in (digests empty, for import to compute).
func FromTemplate(t Template, executable string, companions []string) Manifest {
	m := t.Manifest
	m.Argv = append([]string(nil), t.Manifest.Argv...)
	m.Executable = executable
	m.Companions = nil
	for i, path := range companions {
		if i >= len(t.Companions) || path == "" {
			continue
		}
		tc := t.Companions[i]
		m.Companions = append(m.Companions, Companion{Path: path, OnPath: tc.OnPath, VersionArgv: append([]string(nil), tc.VersionArgv...), VersionFormat: tc.VersionFormat})
	}
	return m
}
