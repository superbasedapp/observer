//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// security_scan_image_driver.go is the driver switch of `observer security
// scan image` (OS and CI vulnerability scanning plan section 6.7, operator
// ruling Q6, lane OS-2 T): [security.scan.image] driver = "scalibr" (route
// A, security.scan.os, security_scan_image.go) or "trivy"
// (security.scan.image.trivy, security_scan_image_trivy.go), the one-off
// --driver flag, the `driver` verb that writes the key, and the status
// lines and dashboard state both drivers share. It also holds the input
// helpers both drivers use (the location, the report), moved here from the
// route A file so a build without SCALIBR (the developer distro, where
// Trivy is the only image driver) still has them.
//
// After a switch the other driver's open findings stay open and listed: a
// finding is closed only by a full scan of the same driver (StaleFindings
// filters by driver id), and a Trivy run says so in a note.

// The driver key and its two values.
const (
	imageDriverKey     = "security.scan.image.driver"
	imageDriverScalibr = "scalibr"
	imageDriverTrivy   = "trivy"
	// imageRouteAComponent is route A's catalog row.
	imageRouteAComponent = "security.scan.os"
)

// imageScalibrCompiled reports route A in this build (its omit mark, or
// SCALIBR's, removes it).
func imageScalibrCompiled() bool {
	return !slices.Contains(components.Omitted(), imageRouteAComponent)
}

// defaultImageDriver is what an unset key reads as: SCALIBR where it is
// compiled, else Trivy where that is, else SCALIBR (whose verb then says it
// is not in this build).
func defaultImageDriver() string {
	if !imageScalibrCompiled() && trivyImageCompiled() {
		return imageDriverTrivy
	}
	return imageDriverScalibr
}

// imageDriverChoices are the drivers this build compiles.
func imageDriverChoices() []string {
	var out []string
	if imageScalibrCompiled() {
		out = append(out, imageDriverScalibr)
	}
	if trivyImageCompiled() {
		out = append(out, imageDriverTrivy)
	}
	return out
}

// resolveImageDriver is the driver of one run: the one-off flag, else the
// key, else the default.
func resolveImageDriver(cfg config.Config, flag string) (string, error) {
	name := strings.TrimSpace(flag)
	if name == "" {
		name = cfg.Security.Scan.Image.Driver
	}
	if name == "" {
		return defaultImageDriver(), nil
	}
	if !slices.Contains(config.SecurityImageScanDrivers, name) {
		return "", fmt.Errorf("unknown image driver %q: use %s", name, strings.Join(config.SecurityImageScanDrivers, " or "))
	}
	return name, nil
}

// withImageDriver adds the driver switch to the image verb c (route A's,
// or its stand-in in a build without it): the --driver flag, the driver
// subcommand, and a run that dispatches on the resolved driver.
func withImageDriver(c *cobra.Command) *cobra.Command {
	scalibrRun := c.RunE
	if c.Flags().Lookup("dockerfile") == nil {
		c.Flags().String("dockerfile", "", "the Dockerfile that built the image: findings point at its FROM line")
	}
	if c.Flags().Lookup("json") == nil {
		c.Flags().Bool("json", false, "print the result as JSON")
	}
	c.Flags().String("driver", "", "this run only: scalibr or trivy (default: [security.scan.image] driver)")
	if trivyImageCompiled() {
		c.Hidden = false
		c.Args = cobra.ExactArgs(1)
		c.Short = "Scan a container image's OS packages for known vulnerabilities (security.scan.os, or Trivy: security.scan.image.trivy)"
	}
	c.AddCommand(newSecurityScanImageDriverCmd())
	c.RunE = func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Flags().GetString("config")
		flag, _ := cmd.Flags().GetString("driver")
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return err
		}
		name, err := resolveImageDriver(cfg, flag)
		if err != nil {
			return err
		}
		if name == imageDriverTrivy {
			return runSecurityScanImageTrivyCmd(cmd, args)
		}
		return scalibrRun(cmd, args)
	}
	return c
}

// errTrivyImageNotInBuild is the Trivy image driver's answer in a build
// without it.
var errTrivyImageNotInBuild = errors.New("security.scan.image.trivy is not in this build: images cannot be scanned with Trivy")

// trivyAttribution is the attribution of Trivy's data wherever its results
// are shown.
const trivyAttribution = "Vulnerability data: Trivy's vulnerability database (aquasecurity/trivy-db, Apache-2.0 tooling), " +
	"aggregated from each distribution's security advisories under that source's own terms. Observer downloads it; it never ships it."

// requireTrivyImageSelected refuses the Trivy image verb unless its row, the
// Trivy binary's row and security.deps are all selected (the row's
// Requires holds the same, checked here before anything opens).
func requireTrivyImageSelected(e *depsScanEnv) error {
	snap := componentSnapshotForConfig(e.cfg)
	for _, id := range []string{trivyImageComponent, trivyEngineComponent, securityDepsComponent} {
		if !securitySelected(snap, id) {
			return fmt.Errorf("%s is not selected: add %s (with %s and %s) under [components] in your config",
				id, trivyImageComponent, trivyEngineComponent, securityDepsComponent)
		}
	}
	return nil
}

// The Trivy image driver's rows (literals, so a build without the driver
// still names them).
const (
	trivyImageComponent  = "security.scan.image.trivy"
	trivyEngineComponent = "security.scan.trivy"
)

func runSecurityScanImageTrivyCmd(cmd *cobra.Command, args []string) error {
	if !trivyImageCompiled() {
		return errTrivyImageNotInBuild
	}
	configPath, _ := cmd.Flags().GetString("config")
	dockerfile, _ := cmd.Flags().GetString("dockerfile")
	asJSON, _ := cmd.Flags().GetBool("json")
	in, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	if _, err := os.Stat(in); err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	ctx := cmd.Context()
	e, err := openDepsScanEnv(ctx, configPath)
	if err != nil {
		return err
	}
	defer e.cleanup()
	if err := requireTrivyImageSelected(e); err != nil {
		return err
	}
	rep, err := runImageTrivyScan(ctx, e, in, dockerfile, func() {
		fmt.Fprintln(cmd.ErrOrStderr(), "waiting for another dependency scan (the daemon's or another command's) to finish...")
	})
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if asJSON {
		return writeSecurityJSON(w, map[string]any{"results": []imageScanReport{rep}, "attribution": trivyAttribution})
	}
	writeImageScanReport(w, rep)
	fmt.Fprintf(w, "\n%s\n", trivyAttribution)
	return nil
}

// newSecurityScanImageDriverCmd is `observer security scan image driver
// [scalibr|trivy]`: with a name it writes [security.scan.image] driver
// through `config set`'s checks and writer (R-165 denies it to an agent);
// either way it prints the state.
func newSecurityScanImageDriverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "driver [scalibr|trivy]",
		Short: "Show, or set, which driver scans container images' OS packages ([security.scan.image] driver)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			w := cmd.OutOrStdout()
			if len(args) == 1 {
				if err := setImageDriver(cmd.Context(), w, configPath, args[0]); err != nil {
					return err
				}
			}
			e, err := openDepsScanEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			writeImageDriverState(cmd.Context(), w, e)
			return nil
		},
	}
}

// setImageDriver writes the key (a driver this build compiles only).
func setImageDriver(ctx context.Context, w io.Writer, configPath, name string) error {
	if !slices.Contains(config.SecurityImageScanDrivers, name) {
		return fmt.Errorf("unknown image driver %q: use %s", name, strings.Join(config.SecurityImageScanDrivers, " or "))
	}
	if !slices.Contains(imageDriverChoices(), name) {
		return fmt.Errorf("the %s image driver is not in this build", name)
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: resolved})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	gov, err := configSetGovernance(ctx, cfg)
	if err != nil {
		return err
	}
	plan, err := planConfigSet(cfg, imageDriverKey, name, gov, true)
	if err != nil {
		return err
	}
	if err := writeConfigSet(resolved, plan); err != nil {
		return err
	}
	fmt.Fprintf(w, "set %s = %s (saved to %s)\n", imageDriverKey, name, resolved)
	return nil
}

// imageDriverStatus is the shared part of the dashboard state.
func imageDriverStatus(e *depsScanEnv) *dashapi.ScannerImageStatus {
	name, _ := resolveImageDriver(e.cfg, "")
	st := &dashapi.ScannerImageStatus{
		Driver: name, Configured: e.cfg.Security.Scan.Image.Driver, Default: defaultImageDriver(), Choices: imageDriverChoices(),
		ScalibrCompiled: imageScalibrCompiled(), TrivyCompiled: trivyImageCompiled(),
	}
	if st.Choices == nil {
		st.Choices = []string{}
	}
	fillTrivyImageStatus(e, st)
	return st
}

// writeImageDriverState prints the image driver lines of `observer security
// scan status` and of the driver verb.
func writeImageDriverState(ctx context.Context, w io.Writer, e *depsScanEnv) {
	st := imageDriverStatus(e)
	configured := st.Configured
	if configured == "" {
		configured = "default"
	}
	fmt.Fprintf(w, "image OS packages: driver %s ([security.scan.image] driver: %s; default %s)\n", st.Driver, configured, st.Default)
	compiled := func(b bool) string {
		if b {
			return "in this build"
		}
		return "not in this build"
	}
	fmt.Fprintf(w, "  scalibr (%s): %s\n", imageRouteAComponent, compiled(st.ScalibrCompiled))
	fmt.Fprintf(w, "  trivy (%s): %s\n", trivyImageComponent, compiled(st.TrivyCompiled))
	writeTrivyImageState(ctx, w, st)
}

// --- shared input helpers (both drivers) -------------------------------

// imageScanReport is one image scan as the CLI prints it.
type imageScanReport struct {
	Image     string         `json:"image"`
	Digest    string         `json:"digest,omitempty"`
	Release   string         `json:"release,omitempty"`
	Component string         `json:"component"`
	Driver    string         `json:"driver,omitempty"`
	Result    secscan.Result `json:"result"`
}

func writeImageScanReport(w io.Writer, r imageScanReport) {
	label := "image " + filepath.Base(r.Image)
	if r.Release != "" {
		label += " (" + r.Release + ")"
	}
	if r.Driver != "" {
		label += " [" + r.Driver + "]"
	}
	cov := r.Result.Coverage
	for _, l := range depscan.RunLabels(cov.Notes) {
		label += " (" + l + ")"
	}
	fmt.Fprintf(w, "%s: %s", label, depsOutcomeWords(cov.Outcome))
	if cov.Reason != "" {
		fmt.Fprintf(w, " (%s)", depscan.ReasonWords(cov.Reason))
	}
	fmt.Fprintf(w, ", %d finding(s)\n", len(r.Result.Findings))
	if r.Digest != "" {
		fmt.Fprintf(w, "  digest: %s\n", r.Digest)
	}
	for _, s := range cov.Skipped {
		what := strings.TrimPrefix(s.Path, depscan.EcosystemSkipPrefix)
		fmt.Fprintf(w, "  not scanned: %s: %s\n", what, depscan.ReasonWords(s.Reason))
	}
	for _, f := range r.Result.Findings {
		fmt.Fprintf(w, "  %-8s %s  %s  %s\n", f.Severity, f.Rule.ID, f.EvidenceRedacted, f.Location.RelPath)
	}
	if r.Result.Engine.DatabaseEpoch != "" {
		fmt.Fprintf(w, "  database: %s\n", r.Result.Engine.DatabaseEpoch)
	}
	for _, n := range cov.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}

// imageLocation is where an image's findings point.
type imageLocation struct {
	RelPath string
	Line    int
}

// imageLocationFor is the Dockerfile's last FROM line (the stage that
// produced the image) relative to its checkout when dockerfile is set,
// else the image file's base name.
func imageLocationFor(image, dockerfile string) (imageLocation, error) {
	if dockerfile == "" {
		return imageLocation{RelPath: filepath.Base(image)}, nil
	}
	abs, err := filepath.Abs(dockerfile)
	if err != nil {
		return imageLocation{}, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return imageLocation{}, fmt.Errorf("--dockerfile: %w", err)
	}
	loc := imageLocation{RelPath: filepath.Base(abs), Line: lastFromLine(b)}
	if root, ok := git.FindCheckoutRoot(filepath.Dir(abs)); ok {
		if rel, err := filepath.Rel(root, abs); err == nil && !strings.HasPrefix(rel, "..") {
			loc.RelPath = filepath.ToSlash(rel)
		}
	}
	return loc, nil
}

// lastFromLine returns the 1-based line of the last FROM instruction (0
// when none): an instruction is the first word of a line that does not
// continue the previous one.
func lastFromLine(b []byte) int {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line, last, cont := 0, 0, false
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		wasCont := cont
		cont = strings.HasSuffix(t, "\\")
		if wasCont || t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if f := strings.Fields(t); len(f) > 0 && strings.EqualFold(f[0], "FROM") {
			last = line
		}
	}
	return last
}

// releaseLabel is the release's ecosystem label (the canary table's key):
// its OSV ecosystem without the Red Hat prefix's trailing colons.
func releaseLabel(r osvdb.OSRelease) string { return strings.TrimRight(r.Ecosystem, ":") }
