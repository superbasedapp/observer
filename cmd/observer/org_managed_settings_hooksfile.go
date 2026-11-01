package main

import (
	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/managedsettings"
)

// The cursor and devin Rail B providers of `observer org emit-managed-settings`
// (surface-gap IDE-5 and the IDE-6 managed row): Observer's hooks as the
// tool's administrator hooks file (Cursor enterprise hooks.json, Devin
// Desktop's Cascade system hooks.json), one file per OS. The command text
// comes from the per-node hook writer (hook.ManagedHooksDocument).

// managedHooksProviders maps a --provider value to the hook tool and the
// product name the README uses.
var managedHooksProviders = map[string]struct{ tool, product, source string }{
	"cursor": {"cursor", "Cursor", "https://cursor.com/docs/hooks"},
	"devin":  {"devin", "Devin Desktop (Cascade)", "https://docs.devin.ai/desktop/cascade/hooks"},
}

type emitHooksFileArgs struct {
	provider, scope, outDir, targetOS string
	hookBinary, hookBinaryWin         string
	allOS                             bool
}

func runEmitManagedHooksFile(cmd *cobra.Command, a emitHooksFileArgs) error {
	p := managedHooksProviders[a.provider]
	oses := []string{a.targetOS}
	if a.allOS {
		oses = emitTargetOSes
	}
	var files []managedsettings.ManagedHooksFile
	for _, goos := range oses {
		bin := a.hookBinary
		if goos == "windows" && a.hookBinaryWin != "" {
			bin = a.hookBinaryWin
		}
		doc, path, err := hook.ManagedHooksDocument(p.tool, bin, goos)
		if err != nil {
			return err
		}
		files = append(files, managedsettings.ManagedHooksFile{OS: goos, Path: path, Content: doc})
	}
	arts, err := managedsettings.GenerateManagedHooksFile(managedsettings.ManagedHooksFileOptions{
		Product: p.product, Files: files, Source: p.source,
	})
	if err != nil {
		return err
	}
	out := make([]emittedFile, 0, len(arts.Files)+1)
	for _, f := range arts.Files {
		out = append(out, emittedFile{managedsettings.ManagedHooksFileName(f.OS), f.Content, f.Path})
	}
	out = append(out, emittedFile{"README.md", []byte(arts.Readme), ""})
	return emitFiles(cmd, a.scope, a.outDir, out)
}
