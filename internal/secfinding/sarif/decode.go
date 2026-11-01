package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Decoder caps (section 4.5.3: strict size, depth and count caps).
const (
	// MaxBytes caps one SARIF document.
	MaxBytes = 32 << 20
	// MaxDepth caps JSON nesting.
	MaxDepth = 64
	// MaxRuns caps runs per document.
	MaxRuns = 16
	// MaxRules caps rules per run.
	MaxRules = 20000
	// MaxResults caps results per run kept; the rest are counted as
	// dropped.
	MaxResults = 10000
	// MaxLocations caps locations kept per result.
	MaxLocations = 8
)

// Errors the decoder returns.
var (
	ErrTooLarge   = errors.New("sarif: document over its size cap")
	ErrTooDeep    = errors.New("sarif: document nested over its depth cap")
	ErrBadVersion = errors.New("sarif: not a SARIF 2.1.0 document")
)

// Log is a decoded SARIF document.
type Log struct {
	Version string
	Runs    []Run
}

// Run is one decoded run.
type Run struct {
	Tool Tool
	// Results are at most MaxResults; Dropped counts the rest.
	Results []Result
	Dropped int
	// RulesDropped counts rules over MaxRules.
	RulesDropped int
}

// Tool is a run's tool driver.
type Tool struct {
	Name    string
	Version string
	Rules   []Rule
}

// Rule is one reportingDescriptor. Text fields are kept raw here; the
// semantic adapter decides what (if anything) is kept.
type Rule struct {
	ID               string
	Name             string
	ShortDescription string
	DefaultLevel     string
	// Tags are properties.tags.
	Tags []string
	// SecuritySeverity is properties["security-severity"] as written.
	SecuritySeverity string
	// Precision is properties.precision.
	Precision string
}

// Location is one physical location: the artifact URI and its region.
// region.snippet is never decoded.
type Location struct {
	URI       string
	URIBaseID string
	StartLine int
	EndLine   int
}

// Result is one decoded result.
type Result struct {
	RuleID    string
	RuleIndex int
	Level     string
	// Message is message.text as written (content-bearing; the adapter
	// decides).
	Message string
	// Locations are at most MaxLocations.
	Locations []Location
	// Fingerprints and PartialFingerprints are kept as written.
	Fingerprints        map[string]string
	PartialFingerprints map[string]string
	// Properties are the scalar string properties of the result.
	Properties map[string]string
}

// wire types: the field allowlist. Anything not named here is ignored by
// encoding/json, which is how region.snippet stays undecoded.
type wireLog struct {
	Version string    `json:"version"`
	Runs    []wireRun `json:"runs"`
}

type wireRun struct {
	Tool struct {
		Driver struct {
			Name        string     `json:"name"`
			Version     string     `json:"version"`
			SemanticVer string     `json:"semanticVersion"`
			Rules       []wireRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []json.RawMessage `json:"results"`
}

type wireText struct {
	Text string `json:"text"`
}

type wireRule struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	ShortDescription wireText `json:"shortDescription"`
	DefaultConfig    struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]json.RawMessage `json:"properties"`
}

type wireResult struct {
	RuleID              string                     `json:"ruleId"`
	RuleIndex           *int                       `json:"ruleIndex"`
	Level               string                     `json:"level"`
	Message             wireText                   `json:"message"`
	Locations           []wireLocation             `json:"locations"`
	Fingerprints        map[string]string          `json:"fingerprints"`
	PartialFingerprints map[string]string          `json:"partialFingerprints"`
	Properties          map[string]json.RawMessage `json:"properties"`
}

type wireLocation struct {
	Physical struct {
		Artifact struct {
			URI       string `json:"uri"`
			URIBaseID string `json:"uriBaseId"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
			EndLine   int `json:"endLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// Decode parses one SARIF document under the caps.
func Decode(data []byte) (*Log, error) {
	if len(data) > MaxBytes {
		return nil, ErrTooLarge
	}
	if depth(data) > MaxDepth {
		return nil, ErrTooDeep
	}
	var w wireLog
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("sarif.Decode: %w", err)
	}
	if w.Version != "2.1.0" {
		return nil, ErrBadVersion
	}
	out := &Log{Version: w.Version}
	runs := w.Runs
	if len(runs) > MaxRuns {
		runs = runs[:MaxRuns]
	}
	for _, wr := range runs {
		out.Runs = append(out.Runs, decodeRun(wr))
	}
	return out, nil
}

func decodeRun(wr wireRun) Run {
	d := wr.Tool.Driver
	r := Run{Tool: Tool{Name: d.Name, Version: d.Version}}
	if r.Tool.Version == "" {
		r.Tool.Version = d.SemanticVer
	}
	rules := d.Rules
	if len(rules) > MaxRules {
		r.RulesDropped = len(rules) - MaxRules
		rules = rules[:MaxRules]
	}
	for _, wru := range rules {
		r.Tool.Rules = append(r.Tool.Rules, Rule{
			ID: wru.ID, Name: wru.Name, ShortDescription: wru.ShortDescription.Text,
			DefaultLevel: wru.DefaultConfig.Level, Tags: stringList(wru.Properties["tags"]),
			SecuritySeverity: scalar(wru.Properties["security-severity"]),
			Precision:        scalar(wru.Properties["precision"]),
		})
	}
	for i, raw := range wr.Results {
		if i >= MaxResults {
			r.Dropped = len(wr.Results) - MaxResults
			break
		}
		var res wireResult
		if err := json.Unmarshal(raw, &res); err != nil {
			r.Dropped++
			continue
		}
		r.Results = append(r.Results, decodeResult(res))
	}
	return r
}

func decodeResult(w wireResult) Result {
	res := Result{
		RuleID: w.RuleID, RuleIndex: -1, Level: w.Level, Message: w.Message.Text,
		Fingerprints: w.Fingerprints, PartialFingerprints: w.PartialFingerprints,
	}
	if w.RuleIndex != nil {
		res.RuleIndex = *w.RuleIndex
	}
	locs := w.Locations
	if len(locs) > MaxLocations {
		locs = locs[:MaxLocations]
	}
	for _, l := range locs {
		res.Locations = append(res.Locations, Location{
			URI: l.Physical.Artifact.URI, URIBaseID: l.Physical.Artifact.URIBaseID,
			StartLine: l.Physical.Region.StartLine, EndLine: l.Physical.Region.EndLine,
		})
	}
	if len(w.Properties) > 0 {
		res.Properties = map[string]string{}
		for k, v := range w.Properties {
			if s := scalar(v); s != "" {
				res.Properties[k] = s
			}
		}
	}
	return res
}

// scalar renders a JSON string or number property as a string; anything
// else is "".
func scalar(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func stringList(raw json.RawMessage) []string {
	var out []string
	if len(raw) == 0 || json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// depth returns the maximum JSON nesting depth of data, outside strings.
func depth(data []byte) int {
	d, max := 0, 0
	inStr, esc := false, false
	for _, c := range data {
		switch {
		case inStr:
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{' || c == '[':
			d++
			if d > max {
				max = d
			}
		case c == '}' || c == ']':
			d--
		}
	}
	return max
}
