// Package gitmodules is the pure reader of a project's git submodule pins
// (spike CPP-0, docs/plans/spikes/CPP-0-online-cpp-deps-2026-11.md): the
// `.gitmodules` file's section names and paths, and the gitlink entries
// (mode 160000) of `git ls-files --stage -z`, joined into one Pin per
// submodule: its path relative to the project root, its local name and
// the commit the superproject pins.
//
// What the online check sends is only a Pin's Commit (to api.osv.dev, by
// cmd/observer security_scan_submodules.go through the
// security.scan.osv.db lane). The parser never keeps a submodule's url:
// it can name a private host or repository, so it is skipped while the
// file is read and is not in any type here. A Pin's Path and Name stay on
// the machine; they are where a finding is shown.
//
// The package does no I/O: the caller reads the file and runs git (through
// internal/gitview's read-only envelope) and hands the bytes in. It imports
// no database, network, exec or filesystem package (imports_test.go).
package gitmodules
