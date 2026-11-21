//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/artifactfind"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// security_scan_artifacts.go is the developer's choice of which build
// artifact folders the SCALIBR driver reads (OS and CI vulnerability
// scanning plan section 14.6, M3L-2 item 4, operator ruling 2026-11-05
// "Item 4 folders"): full artifact scanning is opt-in per folder. Candidate
// folders are discovered by name and file header (internal/secscan/
// artifactfind) and shown; nothing under one is read until the developer
// turns it on here, on the Scanners card, or names it for one run
// (`observer security scan --artifacts <dir>`, an explicit per-run opt-in
// that stores nothing).
//
// The choice is a node-local file in the security directory
// (artifact-dirs.json: project root hash to the folders turned on, relative
// to the project root, forward slashes; no path is stored), read by the
// daemon's schedule, the CLI and "Scan now" alike. It is a posture the
// developer owns: guard rule R-165 denies an agent the verbs below, the
// route and the file (consentRecordPatterns).

// artifactChoiceFile is the choice file's name in the security directory.
const artifactChoiceFile = "artifact-dirs.json"

const (
	// maxArtifactChoiceBytes caps the file read.
	maxArtifactChoiceBytes = 1 << 20
	// maxArtifactChoiceProjects caps the projects the file remembers.
	maxArtifactChoiceProjects = 512
)

// artifactEnableText is what turning a folder on does, the words the CLI
// and the Scanners card show.
const artifactEnableText = "Turning a folder on lets every scan of this project (the scheduled one, Scan now, the command line) open the programs, Java archives and Python wheels in it and read the package list each one declares about itself: a Go program's build info, a Rust program's cargo-auditable section, a JAR's pom.properties, a wheel's metadata. Files are opened read-only and held to 256 MiB; nothing is run, decompiled or sent anywhere. A Go program's embedded standard library is matched by its Go version and reads \"potentially affected\" unless more is known. A folder that is off is never opened."

// artifactChoices maps a project root hash to the artifact folders turned on
// for it.
type artifactChoices map[string][]string

// artifactChoicePath is the choice file under the security directory dir.
func artifactChoicePath(dir string) string { return filepath.Join(dir, artifactChoiceFile) }

// readArtifactChoices reads the choice file; a missing, oversized or
// unreadable file is no choice (nothing is on).
func readArtifactChoices(dir string) artifactChoices {
	out := artifactChoices{}
	f, err := os.Open(artifactChoicePath(dir))
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxArtifactChoiceBytes+1))
	if err != nil || len(b) > maxArtifactChoiceBytes {
		return out
	}
	var raw artifactChoices
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	for k, v := range raw {
		if clean, err := depscan.CleanArtifactDirs(v); err == nil && len(clean) > 0 {
			out[k] = clean
		}
	}
	return out
}

// writeArtifactChoices writes the choice file atomically.
func writeArtifactChoices(dir string, c artifactChoices) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := artifactChoicePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, artifactChoicePath(dir))
}

// enabledArtifactDirs is the folders turned on for the project at root.
func enabledArtifactDirs(dir, root string) []string {
	return readArtifactChoices(dir)[secposture.ProjectRootHash(root)]
}

// projectRelDir turns a folder named by the developer (relative to the
// project root, or absolute inside it) into the stored form: relative,
// forward slashes, cleaned (depscan.CleanArtifactDirs). The folder need not
// exist (a disable of a folder since removed must work).
func projectRelDir(root, d string) (string, error) {
	abs := d
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, d)
	}
	rel, err := filepath.Rel(root, filepath.Clean(abs))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s: must be a folder inside the project %s", d, root)
	}
	out, err := depscan.CleanArtifactDirs([]string{filepath.ToSlash(rel)})
	if err != nil || len(out) != 1 {
		return "", fmt.Errorf("%s: %w", d, depscan.ErrArtifactDir)
	}
	return out[0], nil
}

// setArtifactDir turns one folder of the project at root on or off and
// returns the folders on afterwards. Turning one on needs an existing folder
// inside the project.
func setArtifactDir(dir, root, d string, on bool) ([]string, error) {
	rel, err := projectRelDir(root, d)
	if err != nil {
		return nil, err
	}
	if on {
		if fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("%s: not a folder of the project", d)
		}
	}
	all := readArtifactChoices(dir)
	key := secposture.ProjectRootHash(root)
	cur := all[key]
	switch {
	case on && !slices.Contains(cur, rel):
		cur = append(slices.Clone(cur), rel)
	case !on:
		cur = slices.DeleteFunc(slices.Clone(cur), func(s string) bool { return s == rel })
	}
	clean, err := depscan.CleanArtifactDirs(cur)
	if err != nil {
		return nil, err
	}
	if len(clean) == 0 {
		delete(all, key)
	} else {
		if _, known := all[key]; !known && len(all) >= maxArtifactChoiceProjects {
			return nil, errors.New("too many projects with artifact folders turned on")
		}
		all[key] = clean
	}
	if err := writeArtifactChoices(dir, all); err != nil {
		return nil, err
	}
	return clean, nil
}

// artifactScanPlan is what one scan of a project reads: the folders turned
// on (or named for this run) and the discovered candidates that are left
// off (under which not even an archive found by name is read).
type artifactScanPlan struct {
	On  []string
	Off []string
}

// planArtifactScan builds the plan for the project at root: the folders the
// developer turned on, plus the ones named for this run, and every
// discovered candidate folder not among them as off. The discovery reads
// folder names and file headers only (artifactfind).
func planArtifactScan(dir, root string, named []string) artifactScanPlan {
	on := depscan.ArtifactDirs(append(slices.Clone(enabledArtifactDirs(dir, root)), named...))
	plan := artifactScanPlan{On: on}
	found, err := artifactfind.Discover(os.DirFS(root))
	if err != nil {
		return plan
	}
	for _, f := range found {
		if !slices.Contains(on, f.Dir) {
			plan.Off = append(plan.Off, f.Dir)
		}
	}
	return plan
}

// artifactFolders is the project's candidate folders and which are on, for
// the card and `artifacts list`.
func artifactFolders(dir, root string) dashapi.ArtifactFolders {
	out := dashapi.ArtifactFolders{Project: root, Folders: []dashapi.ArtifactFolder{}, Text: artifactEnableText, DriverCompiled: scalibrfacade.Compiled}
	on := enabledArtifactDirs(dir, root)
	rows := map[string]dashapi.ArtifactFolder{}
	fsys := os.DirFS(root)
	found, _ := artifactfind.Discover(fsys)
	for _, f := range found {
		rows[f.Dir] = artifactRow(f, slices.Contains(on, f.Dir), true)
	}
	for _, d := range on {
		if _, ok := rows[d]; ok {
			continue
		}
		fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(d)))
		if err != nil || !fi.IsDir() {
			rows[d] = dashapi.ArtifactFolder{Dir: d, Enabled: true, Summary: "folder not found"}
			continue
		}
		rows[d] = artifactRow(artifactfind.Inspect(fsys, d), true, true)
	}
	for _, r := range rows {
		out.Folders = append(out.Folders, r)
	}
	sort.Slice(out.Folders, func(i, j int) bool { return out.Folders[i].Dir < out.Folders[j].Dir })
	return out
}

func artifactRow(f artifactfind.Folder, enabled, present bool) dashapi.ArtifactFolder {
	return dashapi.ArtifactFolder{
		Dir: f.Dir, Enabled: enabled, Default: f.Default, Present: present,
		Summary: f.Summary(), Counts: f.Counts, Bytes: f.Bytes, Truncated: f.Truncated,
	}
}

// newSecurityScanArtifactsCmd is `observer security scan artifacts`: list
// the project's candidate artifact folders, turn one on or off. The verbs
// that change the choice are the developer's (guard rule R-165).
func newSecurityScanArtifactsCmd() *cobra.Command {
	artifacts := &cobra.Command{
		Use:   "artifacts",
		Short: "List the project's build artifact folders and which are turned on for scanning (off until you turn one on)",
		Long: "Lists the folders of the project that look like build output (bin/, dist/, target/release/ and the like, found by\n" +
			"folder name and file header, nothing read beyond the first bytes of each file) and which of them the\n" +
			"dependency scan reads. Every folder is off until you turn it on with `enable`; `observer security scan\n" +
			"--artifacts DIR` reads a folder for one run only.\n\n" + artifactEnableText,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runArtifactsList(cmd) },
	}
	artifacts.PersistentFlags().String("project", ".", "the project folder")
	artifacts.AddCommand(
		&cobra.Command{
			Use: "list", Short: "List the candidate folders and which are on", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return runArtifactsList(cmd) },
		},
		&cobra.Command{
			Use: "enable DIR", Short: "Turn a folder of the project on for artifact scanning", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error { return runArtifactsSet(cmd, args[0], true) },
		},
		&cobra.Command{
			Use: "disable DIR", Short: "Turn a folder of the project off for artifact scanning", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error { return runArtifactsSet(cmd, args[0], false) },
		},
	)
	return artifacts
}

// artifactProjectRoot is the --project folder, absolute and existing.
func artifactProjectRoot(cmd *cobra.Command) (string, error) {
	p, _ := cmd.Flags().GetString("project")
	root, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory", root)
	}
	return root, nil
}

// artifactSecurityDir is the security directory of the config in force.
func artifactSecurityDir(cmd *cobra.Command) (string, error) {
	configPath, _ := cmd.Flags().GetString("config")
	if err := requireDepsScanSelected(configPath); err != nil {
		return "", err
	}
	return securityDirFor(configPath)
}

func runArtifactsList(cmd *cobra.Command) error {
	root, err := artifactProjectRoot(cmd)
	if err != nil {
		return err
	}
	dir, err := artifactSecurityDir(cmd)
	if err != nil {
		return err
	}
	writeArtifactList(cmd.OutOrStdout(), root, artifactFolders(dir, root))
	return nil
}

// writeArtifactList prints the candidate folders, one per line.
func writeArtifactList(w io.Writer, root string, v dashapi.ArtifactFolders) {
	fmt.Fprintf(w, "Artifact folders of %s (a folder is off until you turn it on):\n", root)
	if len(v.Folders) == 0 {
		fmt.Fprintln(w, "  none found (bin/, dist/, target/release/ and other build output folders show here once they exist)")
	}
	for _, f := range v.Folders {
		state := "off"
		if f.Enabled {
			state = "ON "
		}
		fmt.Fprintf(w, "  [%s] %s: %s\n", state, f.Dir, f.Summary)
	}
	fmt.Fprintln(w, "Turn one on: observer security scan artifacts enable DIR. One run only: observer security scan --artifacts DIR.")
}

func runArtifactsSet(cmd *cobra.Command, d string, on bool) error {
	root, err := artifactProjectRoot(cmd)
	if err != nil {
		return err
	}
	dir, err := artifactSecurityDir(cmd)
	if err != nil {
		return err
	}
	if !scalibrfacade.Compiled {
		return errors.New("the SCALIBR driver, which reads build artifacts, is not in this build")
	}
	if _, err := setArtifactDir(dir, root, d, on); err != nil {
		return err
	}
	rel, _ := projectRelDir(root, d)
	if on {
		fmt.Fprintf(cmd.OutOrStdout(), "Artifact folder %s is on for %s: every scan of the project now reads the programs, archives and wheels in it.\n", rel, root)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Artifact folder %s is off for %s.\n", rel, root)
	return nil
}

// securityDirFor is the security directory of the config at configPath.
func securityDirFor(configPath string) (string, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return "", err
	}
	return secposture.LayoutFor(resolved).Dir, nil
}
