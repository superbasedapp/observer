//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components/sbom"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secinventory"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secsbom"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

// security_sbom.go is the cmd seam of the project SBOM (security coverage
// gaps plan item 2): every dependency scan hands its inventory to the one
// snapshot owner (internal/secinventory, through inventorySink), `observer
// security sbom export` renders the stored inventory as CycloneDX 1.5
// (internal/components/sbom.RenderInventory), and `observer security sbom
// scan <file>` matches the packages an SBOM file lists (internal/secsbom)
// through the scan child's sbom kind, recorded under its own driver id
// (depscan.SBOMID) so it never reads as the project's own scan. Nothing
// here reaches the network.

// errNoInventory is the export's answer for a project never scanned.
var errNoInventory = errors.New("no dependency inventory for this project yet: run `observer security scan` first")

// inventorySink returns the dependency drivers' inventory sink: the
// snapshot owner applies the precedence rule (a write failure is logged),
// then, when [security.licenses] names a policy, the project's licence
// findings are recorded (licenceAfterScan).
func (e *depsScanEnv) inventorySink() func(root, driver string, pkgs []depscan.Package) {
	dir, logger := e.dir, e.logger
	return func(root, driver string, pkgs []depscan.Package) {
		if _, err := secinventory.Replace(dir, secposture.ProjectRootHash(root), inventorySnapshot(driver, pkgs, time.Now()), time.Now()); err != nil && logger != nil {
			logger.Warn("security: the dependency inventory could not be stored", "err", err)
		}
		e.licenceAfterScan(root)
	}
}

// inventorySnapshot keeps the rows an SBOM should list: dependency rows
// with a name and a version, never a locally developed package.
func inventorySnapshot(driver string, pkgs []depscan.Package, now time.Time) secinventory.Snapshot {
	s := secinventory.Snapshot{Driver: driver, ScanTime: now.UTC()}
	for _, p := range pkgs {
		if p.Local || p.Name == "" {
			continue
		}
		s.Packages = append(s.Packages, secinventory.Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Path: p.Path, Extractor: p.Extractor})
	}
	return s
}

// renderProjectSBOM renders a stored snapshot as CycloneDX JSON; licences
// come from licences (eco/name/version key), when given.
func renderProjectSBOM(projectRoot string, snap secinventory.Snapshot, licences map[string][]string) ([]byte, error) {
	pkgs := make([]sbom.InventoryPackage, 0, len(snap.Packages))
	for _, p := range snap.Packages {
		purl, _ := secsbom.PurlFor(p.Ecosystem, p.Name, p.Version)
		pkgs = append(pkgs, sbom.InventoryPackage{
			Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Purl: purl, Path: p.Path,
			Licenses: licences[p.Ecosystem+"\x00"+p.Name+"\x00"+p.Version],
		})
	}
	return sbom.RenderInventory(sbom.InventoryMeta{
		ProjectName: filepath.Base(projectRoot), Tool: "observer", ScanTime: snap.ScanTime, Truncated: snap.Truncated,
	}, pkgs)
}

func newSecuritySBOMCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "sbom",
		Short: "Export a project's SBOM (CycloneDX 1.5) or check the packages an SBOM file lists (component security.deps)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	var project, out string
	export := &cobra.Command{
		Use:   "export",
		Short: "Write the project's SBOM, CycloneDX 1.5 JSON, from its last dependency scan's inventory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := securityProjectRoot(project)
			if err != nil {
				return err
			}
			configPath, _ := cmd.Flags().GetString("config")
			e, err := openDepsScanEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			snap, ok := secinventory.Load(e.dir, secposture.ProjectRootHash(root))
			if !ok {
				return errNoInventory
			}
			doc, err := renderProjectSBOM(root, snap, projectLicenceMap(root, snap))
			if err != nil {
				return err
			}
			if out == "" || out == "-" {
				_, err = cmd.OutOrStdout().Write(doc)
				return err
			}
			if err := os.WriteFile(out, doc, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %s: %d packages from the %s scan of %s.\n", out, len(snap.Packages), snap.Driver, snap.ScanTime.Local().Format(time.RFC1123))
			return nil
		},
	}
	export.Flags().StringVar(&project, "project", "", "project directory (default: the git root of the working directory)")
	export.Flags().StringVar(&out, "out", "", "file to write (default: standard output)")
	var scanProject string
	var asJSON bool
	scan := &cobra.Command{
		Use:   "scan <file>",
		Short: "Match the packages a CycloneDX or SPDX JSON file lists against the local OSV database",
		Long: "Reads a CycloneDX (1.4 to 1.6) or SPDX 2.x JSON SBOM another tool wrote, and matches the packages\n" +
			"it lists through the dependency scan child against the local OSV database, one ecosystem at a time.\n" +
			"Findings are stored against the project, labelled as coming from an SBOM (driver sbom-import), and\n" +
			"never count as the project's own dependency scan. Nothing is sent anywhere.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := securityProjectRoot(scanProject)
			if err != nil {
				return err
			}
			configPath, _ := cmd.Flags().GetString("config")
			e, err := openDepsScanEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			res, err := e.scanSBOMFile(cmd.Context(), root, args[0], extrunhost.NewRunner(extrunhost.Options{}))
			if err != nil {
				return err
			}
			if asJSON {
				return writeSecurityJSON(cmd.OutOrStdout(), map[string]any{"result": res, "attribution": OSVAttribution})
			}
			writeScanReport(cmd.OutOrStdout(), depsScanReport{Driver: depscan.SBOMID, Component: depscan.ScalibrComponent, Result: res})
			fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n", OSVAttribution)
			return nil
		},
	}
	scan.Flags().StringVar(&scanProject, "project", "", "the project to store the findings against (default: the git root of the working directory)")
	scan.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON")
	c.AddCommand(export, scan)
	return c
}

// sbomFileMax caps the SBOM file read.
const sbomFileMax = secsbom.MaxSBOMBytes

// scanSBOMFile reads an SBOM file, matches its packages in the scan child
// and records the run under depscan.SBOMID. The file's path relative to
// the project (else its base name) locates the findings.
func (e *depsScanEnv) scanSBOMFile(ctx context.Context, root, file string, runner *extrun.Runner) (secscan.Result, error) {
	f, err := os.Open(file) //nolint:gosec // G304: the SBOM file the developer named; only read and parsed.
	if err != nil {
		return secscan.Result{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, sbomFileMax+1))
	_ = f.Close()
	if err != nil {
		return secscan.Result{}, err
	}
	doc, err := secsbom.Read(data)
	if err != nil {
		return secscan.Result{}, fmt.Errorf("%s: %w", file, err)
	}
	rel := filepath.Base(file)
	if abs, err := filepath.Abs(file); err == nil {
		if r, err := filepath.Rel(root, abs); err == nil && filepath.IsLocal(r) {
			rel = filepath.ToSlash(r)
		}
	}
	pkgs := make([]depscan.Package, 0, len(doc.Packages))
	for _, p := range doc.Packages {
		pkgs = append(pkgs, depscan.Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Path: rel, Extractor: secsbom.ExtractorFor(doc.Format)})
	}
	t := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual}
	engine := secscan.EngineIdentity{Name: depscan.SBOMID, Version: depscan.SCALIBRVersion}
	started := time.Now()
	res := e.runSBOMChild(ctx, runner, t, engine, pkgs)
	if doc.Truncated {
		res.Coverage.Notes = append(res.Coverage.Notes, fmt.Sprintf("the SBOM lists more than %d packages; the rest were not checked", secsbom.MaxSBOMPackages))
	}
	if doc.Skipped > 0 {
		res.Coverage.Notes = append(res.Coverage.Notes, fmt.Sprintf("%d SBOM entries name no package Observer can match (no purl, or an ecosystem with no database)", doc.Skipped))
	}
	// An SBOM run closes nothing: what a file another tool wrote leaves out
	// proves nothing about the project.
	if _, err := secsvc.RecordRun(ctx, e.st, t, res, started, time.Since(started), secsvc.Gone{}, securityRT.notify); err != nil {
		return res, err
	}
	return res, nil
}

// runSBOMChild runs the scan child with the sbom kind over pkgs.
func (e *depsScanEnv) runSBOMChild(ctx context.Context, runner *extrun.Runner, t secscan.Target, engine secscan.EngineIdentity, pkgs []depscan.Package) secscan.Result {
	in := depdriver.Input{DriverID: depscan.SBOMID, Target: t, Engine: engine}
	if !scalibrfacade.Compiled {
		in.RunReason = depscan.ReasonNotCompiled
		return depdriver.Result(in)
	}
	if len(pkgs) == 0 {
		in.RunReason = "no_packages"
		return depdriver.Result(in)
	}
	epochs, err := e.db.Installed()
	if err != nil {
		in.Failed, in.RunReason = true, depscan.ReasonEngineFailed
		return depdriver.Result(in)
	}
	exe, err := depsSelfExecutable()
	if err != nil {
		in.Failed, in.RunReason = true, depscan.ReasonEngineFailed
		return depdriver.Result(in)
	}
	req, err := depdriver.ScalibrRequest(exe, t.ProjectRoot, depscan.ChildRequest{
		Version: depscan.ProtocolVersion, Kind: depscan.KindSBOM, Root: t.ProjectRoot, DBDir: e.db.Dir(),
		Epochs: e.matchEpochs(epochs), GOOS: runtime.GOOS, Packages: pkgs,
	})
	if err != nil {
		in.Failed, in.RunReason = true, depscan.ReasonEngineFailed
		return depdriver.Result(in)
	}
	out := runner.Run(ctx, req)
	if out.Digests.Binary != "" {
		in.Engine.Digest = out.Digests.Binary
	}
	resp, perr := depdriver.ParseChild(out)
	if perr != nil || resp.Kind != depscan.KindSBOM {
		in.Failed, in.RunReason = true, depscan.ReasonEngineFailed
		return depdriver.Result(in)
	}
	in.Response = resp
	in.Notes = []string{depscan.NotIsolatedPrefix + ": the SBOM check's scan child reads only the packages it is handed and the local database."}
	return depdriver.Result(in)
}
