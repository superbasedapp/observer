package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/components"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process exit, so tests drive it directly.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	if code, handled := runCustom(args[0], args[1:], stdout, stderr); handled {
		return code
	}
	switch args[0] {
	case "proof":
		return runProof(args[1:], stdout, stderr)
	case "sbom":
		return runSBOM(args[1:], stdout, stderr)
	}
	fs := newFlagSet(args[0], stderr)
	out := fs.String("o", components.DocsPath, "path of the generated reference")
	distro := fs.String("distro", "", "prebuilt node distro: minimal, developer, managed or full")
	image := fs.String("image", "", "observer-org image: full or core (tags only)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "gen-docs":
		if p := components.Validate(); len(p) != 0 {
			fmt.Fprintf(stderr, "catalog has %d problems:\n%s\n", len(p), strings.Join(p, "\n"))
			return 1
		}
		//nolint:gosec // G306: a generated, version-controlled docs page, never credentials or captured data.
		if err := os.WriteFile(*out, []byte(components.RenderMarkdown()), 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote %s\n", *out)
		return 0
	case "check":
		if p := components.Validate(); len(p) != 0 {
			fmt.Fprintf(stderr, "catalog has %d problems:\n%s\n", len(p), strings.Join(p, "\n"))
			return 1
		}
		got, err := os.ReadFile(*out) //nolint:gosec // G703: a repo generator reading the path given on its own command line
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if !bytes.Equal(got, []byte(components.RenderMarkdown())) {
			fmt.Fprintf(stderr, "%s is stale: run go run ./cmd/sbo-components gen-docs\n", *out)
			return 1
		}
		fmt.Fprintf(stdout, "%s is current (catalog v%d)\n", *out, components.CatalogVersion)
		return 0
	case "distros":
		// The distros whose build passes a tag set: every prebuilt distro
		// with a stamp. full is the plain build and has none, so it is not
		// listed. scripts/omit-tag-check.sh loops over this list.
		for _, d := range components.Distros() {
			if components.DistroTag(d) != "" {
				fmt.Fprintln(stdout, d)
			}
		}
		return 0
	case "tags", "ids", "validate":
		if args[0] == "tags" && *image != "" {
			i := components.Image(*image)
			if i != components.ImageFull && i != components.ImageCore {
				fmt.Fprintf(stderr, "--image must be full or core (got %q)\n", *image)
				return 2
			}
			fmt.Fprintln(stdout, strings.Join(components.ImageTags(i), ","))
			return 0
		}
		d := components.Distro(*distro)
		if !d.Valid() {
			fmt.Fprintf(stderr, "--distro must be one of minimal, developer, managed, full (got %q)\n", *distro)
			return 2
		}
		switch args[0] {
		case "tags":
			fmt.Fprintln(stdout, strings.Join(components.DistroTags(d), ","))
		case "ids":
			for _, id := range components.InDistro(d) {
				fmt.Fprintln(stdout, id)
			}
		case "validate":
			if p := components.ValidateSelection(components.BinaryNode, components.InDistro(d)); len(p) != 0 {
				fmt.Fprintln(stderr, strings.Join(p, "\n"))
				return 1
			}
			fmt.Fprintf(stdout, "%s: %d components, digest %s\n", d, len(components.InDistro(d)), components.Digest(components.InDistro(d)))
		}
		return 0
	default:
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: sbo-components gen-docs|check [-o path] | distros | tags|ids|validate (--distro <minimal|developer|managed|full> | --manifest <m.toml>) | tags --image <full|core> | proof|sbom (--distro <name> | --image <full|core> | --manifest <m.toml>) --binary <path> | manifest|ldflags|build --manifest <m.toml>")
}

// newFlagSet returns a flag set that reports to stderr and never exits.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}
