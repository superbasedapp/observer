package managedsettings

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Administrator hooks files (surface-gap IDE-5 and the IDE-6 managed row):
// Cursor's enterprise hooks.json and Devin Desktop's Cascade system
// hooks.json. Both tools MERGE the administrator file with the user's, so
// a hook deployed there runs whatever the developer does with their own
// files, and a deny from it still wins (Cursor). The document bytes come
// from the per-node hook writer (internal/hook.ManagedHooksDocument, one
// owner of the command text); this generator adds the deploy steps and the
// README, with the hold stated honestly: the file is the only channel these
// vendors document for hooks, so a macOS profile or an ADMX cannot carry
// them, and the file is only as tamper-proof as its directory.

// ManagedHooksFile is one per-OS administrator hooks file.
type ManagedHooksFile struct {
	// OS is the GOOS it deploys to; Path where; Content its bytes.
	OS, Path string
	Content  []byte
}

// ManagedHooksFileOptions configures the generator.
type ManagedHooksFileOptions struct {
	// Product names the tool in the README ("Cursor", "Devin Desktop").
	Product string
	// Files are the per-OS documents, in the order to list them.
	Files []ManagedHooksFile
	// Source is the vendor page the file layer is grounded in.
	Source string
}

// ManagedHooksFileArtifacts is the generated output.
type ManagedHooksFileArtifacts struct {
	Files  []ManagedHooksFile
	Readme string
}

// managedHooksInstall are the deploy steps per OS (the file channel).
var managedHooksInstall = map[string][]string{
	"linux": {
		`sudo install -d -m 0755 -o root -g root "<dir>"`,
		`sudo install -m 0644 -o root -g root "<file>" "<path>"`,
	},
	"darwin": {
		`sudo install -d -m 0755 -o root -g wheel "<dir>"`,
		`sudo install -m 0644 -o root -g wheel "<file>" "<path>"`,
		"Fleet: ship it as a package or an MDM script; there is no profile key for hooks.",
	},
	"windows": {
		`From an elevated prompt: mkdir "<dir>" and copy "<file>" "<path>"`,
		`icacls "<dir>" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"`,
		"Fleet: deploy the file with Intune or Group Policy Preferences (Files). Without the icacls step a standard user can replace it, " +
			"and Observer then does not rely on it.",
	},
}

// GenerateManagedHooksFile validates the per-OS documents and writes the
// README.
func GenerateManagedHooksFile(opts ManagedHooksFileOptions) (ManagedHooksFileArtifacts, error) {
	if strings.TrimSpace(opts.Product) == "" || len(opts.Files) == 0 {
		return ManagedHooksFileArtifacts{}, fmt.Errorf("managedsettings: an administrator hooks file needs a product and at least one file")
	}
	for _, f := range opts.Files {
		if _, ok := managedHooksInstall[f.OS]; !ok || !strings.ContainsAny(f.Path, `/\`) {
			return ManagedHooksFileArtifacts{}, fmt.Errorf("managedsettings: %s hooks file for %q has no deploy path", opts.Product, f.OS)
		}
		var probe struct {
			Hooks map[string]json.RawMessage `json:"hooks"`
		}
		if err := json.Unmarshal(f.Content, &probe); err != nil || len(probe.Hooks) == 0 {
			return ManagedHooksFileArtifacts{}, fmt.Errorf("managedsettings: %s hooks file for %s is not a hooks document", opts.Product, f.OS)
		}
	}
	return ManagedHooksFileArtifacts{Files: opts.Files, Readme: managedHooksReadme(opts)}, nil
}

// ManagedHooksFileName is the artifact file name for one OS.
func ManagedHooksFileName(goos string) string { return "hooks." + goos + ".json" }

func managedHooksReadme(opts ManagedHooksFileOptions) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Observer administrator hooks for %s\n\n", opts.Product))
	b.WriteString(fmt.Sprintf("%s merges its administrator hooks file with the user's own, so Observer's\n", opts.Product))
	b.WriteString("hooks run whatever the developer does with their files. Each command runs the\n")
	b.WriteString("node's `observer hook ...`, the command `observer init` registers per node, so\n")
	b.WriteString("`observer` must resolve on the node (or regenerate with `--hook-binary`).\n\n")
	b.WriteString("A node whose administrator file carries Observer's entries stands its own\n")
	b.WriteString("per-node registration down for those events, so nothing fires twice. It relies\n")
	b.WriteString("on the file only when an administrator owns it and its directory (root, or\n")
	b.WriteString("Administrators / SYSTEM on Windows); `observer doctor` says which.\n\n")
	b.WriteString("The file is the only channel the vendor documents for hooks: a macOS\n")
	b.WriteString("configuration profile or an ADMX cannot carry them.\n\n")
	b.WriteString("## Deploy\n\n")
	for _, f := range opts.Files {
		dir := "."
		if i := strings.LastIndexAny(f.Path, `/\`); i > 0 {
			dir = f.Path[:i]
		}
		b.WriteString(fmt.Sprintf("- %s: `%s` to `%s`\n", f.OS, ManagedHooksFileName(f.OS), f.Path))
		for _, st := range managedHooksInstall[f.OS] {
			st = strings.NewReplacer("<dir>", dir, "<file>", ManagedHooksFileName(f.OS), "<path>", f.Path).Replace(st)
			b.WriteString("  - " + st + "\n")
		}
	}
	if opts.Source != "" {
		b.WriteString("\nSource: " + opts.Source + "\n")
	}
	return b.String()
}
