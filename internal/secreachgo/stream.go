package secreachgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Trace is the first frame of one govulncheck finding: the vulnerable
// module, and for a deeper finding its package and function.
type Trace struct {
	OSV      string
	Module   string
	Version  string
	Package  string
	Function string
	Receiver string
}

// Level is a trace's depth: "module", "package" or "symbol".
func (t Trace) Level() string {
	switch {
	case t.Function != "":
		return "symbol"
	case t.Package != "":
		return "package"
	}
	return "module"
}

// Symbol is the trace's function as an OSV record names it
// ("Token.SignedString", "Parse"); "" below symbol level.
func (t Trace) Symbol() string {
	if t.Function == "" {
		return ""
	}
	recv := t.Receiver
	for len(recv) > 0 && recv[0] == '*' {
		recv = recv[1:]
	}
	if recv == "" {
		return t.Function
	}
	return recv + "." + t.Function
}

// streamMessage is the part of a govulncheck JSON message ParseStream
// reads: findings only (the config, progress, SBOM and OSV messages are
// skipped; an OSV entry's prose is never read).
type streamMessage struct {
	Finding *struct {
		OSV   string `json:"osv"`
		Trace []*struct {
			Module   string `json:"module"`
			Version  string `json:"version"`
			Package  string `json:"package"`
			Function string `json:"function"`
			Receiver string `json:"receiver"`
		} `json:"trace"`
	} `json:"finding"`
}

// MaxTraces caps the findings ParseStream keeps.
const MaxTraces = 20000

// ErrTooManyTraces is ParseStream's answer past MaxTraces.
var ErrTooManyTraces = errors.New("secreachgo: govulncheck reported more findings than one check reads")

// ParseStream reads govulncheck's -format json stream (a sequence of JSON
// messages) into the first frame of each finding.
func ParseStream(r io.Reader) ([]Trace, error) {
	dec := json.NewDecoder(r)
	var out []Trace
	for {
		var m streamMessage
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("secreachgo.ParseStream: %w", err)
		}
		if m.Finding == nil || m.Finding.OSV == "" || len(m.Finding.Trace) == 0 || m.Finding.Trace[0] == nil {
			continue
		}
		if len(out) >= MaxTraces {
			return nil, ErrTooManyTraces
		}
		f := m.Finding.Trace[0]
		out = append(out, Trace{OSV: m.Finding.OSV, Module: f.Module, Version: f.Version, Package: f.Package, Function: f.Function, Receiver: f.Receiver})
	}
}
