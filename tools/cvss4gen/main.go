// Command cvss4gen generates internal/secassess/cvss4/tables_gen.go, the data
// tables of the CVSS 4.0 base scorer, from FIRST's own calculator source.
//
// The tables are never typed by hand. The input is a pinned, vendored copy of
// five files of github.com/FIRSTdotorg/cvss-v4-calculator (BSD-2-Clause) plus
// its LICENSE, listed with their commit and sha256 in upstream/UPSTREAM:
//
//	cvss_lookup.js    the score of each of the 270 valid MacroVectors
//	max_composed.js   the maximal vectors of every EQ level
//	max_severity.js   the maximal severity distance of every EQ level
//	cvss_config.js    the valid values of every metric
//	cvss_score.js     the per-metric severity levels, and the algorithm
//
// The generator parses those JavaScript object literals with a strict small
// parser (jslit.go), checks every table against the shapes the CVSS 4.0
// specification fixes (270 valid MacroVectors, the 3 x 2 x 3 x 3 x 3 x 2
// level grid minus the 54 impossible EQ3 = 2 and EQ6 = 0 cases, the metrics'
// value sets, fragments that fix exactly their EQ's metrics), and checks that
// cvss_score.js still contains, word for word, each rule of the algorithm
// that the hand-written Go scorer reproduces (tables.go anchors). Any
// disagreement stops generation with a message naming it.
//
// It runs offline from the vendored copy. upstream/fetch.sh refreshes that
// copy from GitHub at the pinned commit and verifies the sha256 of every
// file; moving to a new upstream commit means running it with a new commit,
// updating UPSTREAM, regenerating and re-running the oracle tests.
//
// Usage (the go:generate line in internal/secassess/cvss4 does this):
//
//	go run ./tools/cvss4gen -upstream tools/cvss4gen/upstream -out internal/secassess/cvss4/tables_gen.go
//	go run ./tools/cvss4gen -check ...   # exit 1 if -out is not what would be generated
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout *os.File) error {
	fs := flag.NewFlagSet("cvss4gen", flag.ContinueOnError)
	upstream := fs.String("upstream", "tools/cvss4gen/upstream", "directory holding the vendored upstream files and UPSTREAM")
	out := fs.String("out", "internal/secassess/cvss4/tables_gen.go", "generated Go file")
	check := fs.Bool("check", false, "do not write; fail if -out differs from what would be generated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	src, err := generate(*upstream)
	if err != nil {
		return err
	}
	if *check {
		cur, err := os.ReadFile(*out) //nolint:gosec // G304: the flag is the generated file's path
		if err != nil {
			return fmt.Errorf("cvss4gen: read %s: %w", *out, err)
		}
		if !bytes.Equal(cur, src) {
			return fmt.Errorf("cvss4gen: %s is out of date; run go generate ./internal/secassess/cvss4", *out)
		}
		_, _ = fmt.Fprintf(stdout, "cvss4gen: %s is current (%d bytes)\n", *out, len(src))
		return nil
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil { //nolint:gosec // G306: a source file in the repository
		return fmt.Errorf("cvss4gen: write %s: %w", *out, err)
	}
	_, _ = fmt.Fprintf(stdout, "cvss4gen: wrote %s (%d bytes)\n", *out, len(src))
	return nil
}
