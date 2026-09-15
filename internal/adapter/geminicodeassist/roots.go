package geminicodeassist

import (
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

// extensionDirName is the extension's own globalStorage subdirectory —
// the VS Code publisher.name id, which is also the ItemTable memento key
// [STATIC-GROUNDED, bundle 2.98.0].
const extensionDirName = "google.geminicodeassist"

// metricsSpoolDirName is the transient token spool `sendMetricsFromDisk`
// drains [STATIC-GROUNDED].
const metricsSpoolDirName = "metrics_to_send"

// checkpointsDirName holds Chat Mode's per-chat checkpoint files
// [STATIC-GROUNDED as a name; contents UNVERIFIED].
const checkpointsDirName = "chat_checkpoint_files"

// stateDBFileName is the VS Code-family shared memento database. The
// Chat Mode threads live in its single ItemTable row keyed
// extensionDirName.
const stateDBFileName = "state.vscdb"

// NO environment override exists. The extension documents none, and the
// bundle read found none — Chat Mode storage is wherever the host editor
// puts its globalStorage, full stop. Do not invent one; an ungrounded
// env knob is a capability claim.

// defaultRoots returns the watch roots for every cross-mount-resolved
// home. Split from rootsForHomes so tests can inject fake homes.
func defaultRoots() []string {
	return rootsForHomes(crossmount.AllHomes())
}

// rootsForHomes composes the watch roots for the given home roots.
//
// Gemini Code Assist is a marketplace extension, so it installs into
// every VS Code-family host, not just Code — the same reasoning that made
// internal/adapter/copilot enumerate vscodehost.GlobalStorageDirs after
// audit finding IDE-14. For each product under each home this emits:
//
//	<globalStorage>/google.geminicodeassist/metrics_to_send   (directory)
//	<globalStorage>/google.geminicodeassist/chat_checkpoint_files (directory)
//	<globalStorage>/state.vscdb                               (FILE, conditional)
//
// A file root is a first-class shape here, exactly as it is for
// internal/adapter/cursor's state.vscdb and internal/adapter/aider's
// per-repo transcripts: the scan walk visits it directly and fsnotify
// watches the file itself. The `-wal` / `-shm` sidecars are never roots.
//
// # state.vscdb ownership decision
//
// state.vscdb is SHARED: one file per editor product, holding every
// extension's memento rows. It therefore cannot be co-owned. The
// watcher dispatches by longest-watched-root prefix, and
// internal/adapter/defaults' TestRegistryRootsNonOverlapping fails the
// build if two adapters declare roots where one is a prefix of the other
// — and an identical file root IS a prefix of itself.
//
// Two products' state.vscdb is already claimed by a sibling package:
//
//   - Cursor, by internal/adapter/cursor — the file is the only on-disk
//     record of a Cursor empty-window conversation. That adapter is
//     REGISTERED, so this is a live claim.
//   - Windsurf, by internal/adapter/windsurf — that package reads the
//     `windsurf.workspaceCascadeMap` memento out of the same file. It is
//     itself an unregistered skeleton today, so the exclusion is
//     forward-looking: it stops the two from colliding on the day either
//     one registers.
//
// This package therefore declares state.vscdb for every vscodehost
// product EXCEPT those two, so that registering it later collides with
// nothing.
//
// Consequence, stated honestly: a Gemini Code Assist Chat Mode thread
// created inside the Cursor or Windsurf desktop app will be invisible to
// this adapter even after grounding, because its memento row lives in a
// file another adapter owns. Closing that gap needs a shared
// multi-adapter state.vscdb reader (one owner, several consumers), not a
// second root — that is a separate design, not a widening.
//
// The `.cursor-server` REMOTE product (vscodehost Host "cursor-remote")
// is NOT excluded: internal/adapter/cursor's cursorGlobalStorageDir
// resolves desktop layouts only, and its matchesStateDBShape requires a
// `/cursor/user/globalstorage/` segment that a `.cursor-server/data/User/
// globalStorage` path does not contain. If cursor ever widens to the
// remote layout, this exclusion list must grow with it.
func rootsForHomes(homes []crossmount.HomeRoot) []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}

	for _, h := range homes {
		for _, ref := range vscodehost.GlobalStorageDirs(h) {
			if ref.Path == "" {
				continue
			}
			extDir := filepath.Join(ref.Path, extensionDirName)
			add(filepath.Join(extDir, metricsSpoolDirName))
			add(filepath.Join(extDir, checkpointsDirName))
			if ownsStateDB(ref.Product) {
				add(filepath.Join(ref.Path, stateDBFileName))
			}
		}
	}
	return roots
}

// stateDBOwnedElsewhere lists the vscodehost product hosts whose
// state.vscdb file root another adapter already declares. See the
// ownership decision in rootsForHomes.
var stateDBOwnedElsewhere = map[string]string{
	"cursor":   "internal/adapter/cursor",
	"windsurf": "internal/adapter/windsurf",
}

// ownsStateDB reports whether this package may declare product p's
// state.vscdb as one of its watch roots.
func ownsStateDB(p vscodehost.Product) bool {
	_, taken := stateDBOwnedElsewhere[strings.ToLower(p.Host)]
	return !taken
}
