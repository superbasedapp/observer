package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// paths are the committed corpus files and the pack, relative to the
// repository root (the command runs from there).
type paths struct {
	corpus string
	pack   string
}

func (p paths) file(name string) string { return filepath.Join(p.corpus, name) }

func defaultPaths() paths {
	return paths{
		corpus: filepath.Join("scripts", "seccorpus", "corpus"),
		pack:   filepath.Join("internal", "secrulepack", "floor", "observer-code"),
	}
}

func main() {
	if err := run(os.Args[1:], defaultPaths()); err != nil {
		fmt.Fprintln(os.Stderr, "seccorpus:", err)
		os.Exit(1)
	}
}

func run(args []string, p paths) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seccorpus clone|scan|packets|labels|measure|sample|record|table [flags]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dest := fs.String("dest", "", "scratch directory of the clones (outside this checkout)")
	self := fs.String("self", ".", "this repository's local checkout")
	bin := fs.String("opengrep", "", "the pinned Opengrep binary")
	jobs := fs.Int("jobs", runtime.NumCPU(), "Opengrep -j")
	out := fs.String("out", "", "packets directory (scratch, never committed)")
	batch := fs.Int("batch", 60, "findings per packet file")
	pk := fs.String("packets", "", "packets directory")
	labelSeed := fs.Uint64("label-seed", 20261021, "the seed of the per-rule labelling sample")
	capPerRule := fs.Int("cap", 60, "results labelled per rule (all when fewer)")
	full := fs.String("full", "", "packets: rules labelled in full whatever their count, comma separated (a rule proposed for blocking, P-077)")
	reviewer := fs.String("reviewer", "", "labels: a or b (-in is a directory of per-batch files, batch-NNN.jsonl); record: the spot-checker, agent:<id> of an independent AI reviewer or operator (never a labeller)")
	in := fs.String("in", "", "labels: the directory of one reviewer's per-batch label files")
	seed := fs.Uint64("seed", 20261022, "the sample's seed (recorded in the sample file)")
	per := fs.Int("per", 5, "sample rows per rule")
	max := fs.Int("max", 150, "sample rows in all")
	scope := fs.String("scope", "auto", "sample scope: auto, cleared or all")
	date := fs.String("date", "", "the day the operator answered, YYYY-MM-DD")
	pendingB := fs.Bool("second-pass-pending", false, "measure: accept results labelled by side a only while the side-b batches await their relabel (one pass, nothing may block)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "clone":
		return cloneAll(p, *dest, *self)
	case "scan":
		return scanAll(p, *dest, *bin, *jobs)
	case "packets":
		return writePackets(p, *dest, *out, *batch, *labelSeed, *capPerRule, splitList(*full))
	case "labels":
		return importLabels(p, *pk, *reviewer, *in)
	case "measure":
		return measureWith(p, *pendingB)
	case "sample":
		return drawSample(p, *seed, *per, *max, *scope)
	case "record":
		if err := record(p, *date, *reviewer); err != nil {
			return err
		}
		return writeTable(p)
	case "table":
		return writeTable(p)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// splitList reads a comma-separated list, dropping blanks.
func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
