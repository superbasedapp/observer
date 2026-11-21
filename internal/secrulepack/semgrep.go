package secrulepack

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// semgrep.go is the strict decode of one rule file against the Semgrep
// syntax subset the pack may use. Every key outside it fails the decode
// (yaml KnownFields), so a rule cannot carry a fix, a path filter, an
// option that changes the engine, a project-depends-on check that reaches
// a registry, or any other remote reference.

type ruleFile struct {
	Rules []semRule `yaml:"rules"`
}

type semMetadata struct {
	Category string `yaml:"category"`
	CWE      string `yaml:"cwe"`
}

type semRule struct {
	ID        string       `yaml:"id"`
	Languages []string     `yaml:"languages"`
	Severity  string       `yaml:"severity"`
	Message   string       `yaml:"message"`
	Metadata  *semMetadata `yaml:"metadata"`
	Mode      string       `yaml:"mode"`
	// Search mode: exactly one operator inline.
	patternNode `yaml:",inline"`
	// Taint mode.
	Sources    []patternNode `yaml:"pattern-sources"`
	Sinks      []patternNode `yaml:"pattern-sinks"`
	Sanitizers []patternNode `yaml:"pattern-sanitizers"`
}

type mvRegex struct {
	Metavariable string `yaml:"metavariable"`
	Regex        string `yaml:"regex"`
}

type mvPattern struct {
	Metavariable string `yaml:"metavariable"`
	patternNode  `yaml:",inline"`
}

// patternNode is one pattern operator; exactly one field is set.
type patternNode struct {
	Pattern             string        `yaml:"pattern"`
	Patterns            []patternNode `yaml:"patterns"`
	PatternEither       []patternNode `yaml:"pattern-either"`
	PatternInside       string        `yaml:"pattern-inside"`
	PatternNot          string        `yaml:"pattern-not"`
	PatternNotInside    string        `yaml:"pattern-not-inside"`
	PatternRegex        string        `yaml:"pattern-regex"`
	PatternNotRegex     string        `yaml:"pattern-not-regex"`
	MetavariableRegex   *mvRegex      `yaml:"metavariable-regex"`
	MetavariablePattern *mvPattern    `yaml:"metavariable-pattern"`
	FocusMetavariable   string        `yaml:"focus-metavariable"`
}

// operators returns how many operator fields are set.
func (n patternNode) operators() int {
	c := 0
	for _, set := range []bool{
		n.Pattern != "", n.Patterns != nil, n.PatternEither != nil, n.PatternInside != "",
		n.PatternNot != "", n.PatternNotInside != "", n.PatternRegex != "", n.PatternNotRegex != "",
		n.MetavariableRegex != nil, n.MetavariablePattern != nil, n.FocusMetavariable != "",
	} {
		if set {
			c++
		}
	}
	return c
}

// maxNodes caps the operators of one rule; maxNodeDepth their nesting.
const (
	maxNodes     = 400
	maxNodeDepth = 12
)

var metavariable = regexp.MustCompile(`^\$[A-Z_][A-Z0-9_]*$`)

// checkNode validates one operator and everything under it.
func checkNode(n patternNode, depth int, count *int) error {
	*count++
	switch {
	case depth > maxNodeDepth:
		return errors.New("patterns nest too deep")
	case *count > maxNodes:
		return errors.New("too many pattern operators")
	case n.operators() != 1:
		return fmt.Errorf("a pattern entry must hold exactly one operator (found %d)", n.operators())
	}
	for _, re := range []string{n.PatternRegex, n.PatternNotRegex} {
		if re != "" {
			if err := checkRegex(re); err != nil {
				return err
			}
		}
	}
	if m := n.MetavariableRegex; m != nil {
		if !metavariable.MatchString(m.Metavariable) {
			return fmt.Errorf("metavariable-regex names %q", m.Metavariable)
		}
		if err := checkRegex(m.Regex); err != nil {
			return err
		}
	}
	if m := n.MetavariablePattern; m != nil {
		if !metavariable.MatchString(m.Metavariable) {
			return fmt.Errorf("metavariable-pattern names %q", m.Metavariable)
		}
		if err := checkNode(m.patternNode, depth+1, count); err != nil {
			return err
		}
	}
	if n.FocusMetavariable != "" && !metavariable.MatchString(n.FocusMetavariable) {
		return fmt.Errorf("focus-metavariable names %q", n.FocusMetavariable)
	}
	for _, list := range [][]patternNode{n.Patterns, n.PatternEither} {
		if list != nil && len(list) == 0 {
			return errors.New("an empty patterns or pattern-either list")
		}
		for _, c := range list {
			if err := checkNode(c, depth+1, count); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkRegex refuses a regex Go cannot compile or one over the size cap (a
// Go-compilable regex is a conservative subset of what Opengrep accepts).
func checkRegex(re string) error {
	if len(re) > maxRegexBytes {
		return errors.New("a regex is over the size cap")
	}
	if _, err := regexp.Compile(re); err != nil {
		return fmt.Errorf("regex %q: %w", re, err)
	}
	return nil
}

// checkRuleFile strictly decodes a rule file and checks that it holds
// exactly the one rule the manifest names, with the manifest's languages
// (nil: any listed language), Semgrep severity and CWE ("" skips the
// metadata check, for the canary). It reports whether the rule is taint mode.
func checkRuleFile(b []byte, id string, languages []string, severity, cwe string) (taint bool, err error) {
	if len(b) > MaxRuleBytes {
		return false, fmt.Errorf("%d bytes over the %d byte cap", len(b), MaxRuleBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f ruleFile
	if err := dec.Decode(&f); err != nil {
		return false, fmt.Errorf("not a pack rule file: %w", err)
	}
	var extra ruleFile
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return false, errors.New("a rule file holds exactly one YAML document")
	}
	if len(f.Rules) != 1 {
		return false, fmt.Errorf("%d rules in the file (want exactly one)", len(f.Rules))
	}
	r := f.Rules[0]
	switch {
	case r.ID != id:
		return false, fmt.Errorf("the file's rule id %q is not the manifest's %q", r.ID, id)
	case r.Severity != severity:
		return false, fmt.Errorf("severity %q (the manifest says %q)", r.Severity, severity)
	case r.Message == "" || len(r.Message) > MaxTextBytes:
		return false, errors.New("a message of at most 400 bytes is required")
	case strings.Contains(r.Message, "://"):
		return false, errors.New("a message may not carry a URL")
	case len(r.Languages) == 0:
		return false, errors.New("no languages")
	}
	for _, l := range r.Languages {
		if !slices.Contains(Languages, l) {
			return false, fmt.Errorf("language %q is not supported", l)
		}
	}
	if languages != nil && !slices.Equal(r.Languages, languages) {
		return false, fmt.Errorf("languages %v (the manifest says %v)", r.Languages, languages)
	}
	if cwe != "" && (r.Metadata == nil || r.Metadata.CWE != cwe) {
		return false, fmt.Errorf("metadata.cwe must be %s", cwe)
	}
	count := 0
	switch r.Mode {
	case "", "search":
		if len(r.Sources)+len(r.Sinks)+len(r.Sanitizers) > 0 {
			return false, errors.New("taint keys in a search-mode rule")
		}
		return false, checkNode(r.patternNode, 0, &count)
	case "taint":
		if r.operators() != 0 {
			return false, errors.New("a taint-mode rule takes sources and sinks, not a top-level pattern")
		}
		if len(r.Sources) == 0 || len(r.Sinks) == 0 {
			return false, errors.New("a taint-mode rule needs sources and sinks")
		}
		for _, list := range [][]patternNode{r.Sources, r.Sinks, r.Sanitizers} {
			for _, n := range list {
				if err := checkNode(n, 1, &count); err != nil {
					return false, err
				}
			}
		}
		return true, nil
	}
	return false, fmt.Errorf("mode %q is not allowed", r.Mode)
}
