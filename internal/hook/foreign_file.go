package hook

import "sort"

// foreign_file.go - FU-212: no uninstall deletes a whole file, or a
// directory, that is not Observer's.
//
// FU-192 and FU-207 stopped every writer from overwriting a file or entry
// that is not Observer's, and FU-203 stopped an uninstall from removing a
// foreign ENTRY. This is the deletion half, one rule for every unregister
// path that deletes a whole file (a plugin shim, a Command Code mod, the
// Goose plugin manifest, a dedicated hooks file, the Hermes plugin files):
//
//   - a file is deleted only when it reads as Observer's, by the same
//     recogniser the writer's guard uses (Observer's bytes, its marker, its
//     manifest name), and its bytes are compared again just before the
//     delete (removeEmptyConfigFile), so a file replaced in between is kept;
//   - a file that does not read as Observer's is kept byte for byte, with
//     or without --force, and named in UnregistrationResult.FilesKeptForeign
//     (ForeignFileReason). --force keeps its uninstall meaning for
//     Observer's OWN file whose install checksum no longer matches;
//   - a directory is removed only when it is empty once Observer's own
//     files are gone (os.Remove, never os.RemoveAll over a directory that
//     may hold a file Observer did not write).
//
// Before the rule the Goose manifest was deleted whenever Observer's hooks
// entry was, the native Command Code mod was deleted on a --force uninstall
// without any content check, the plugin shims and the Windows mod were
// deleted with --force whatever they held, and `observer init --hermes
// --uninstall` removed the whole Hermes plugin directory with RemoveAll.

// noteKeptForeignFile records path on res as a whole file kept for
// ForeignFileReason.
func noteKeptForeignFile(res *UnregistrationResult, path string) {
	res.FilesKeptForeign = appendNew(res.FilesKeptForeign, path)
	sort.Strings(res.FilesKeptForeign)
}
