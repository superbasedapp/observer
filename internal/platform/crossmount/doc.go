// Package crossmount discovers extra $HOME-equivalent directories that
// observer should treat as candidate watch roots when an AI tool runs
// on the "other side" of a WSL2/Windows pair.
//
// Concretely:
//
//   - On WSL2 (any Linux host where /mnt/c/Users is statable), each
//     REAL USER directory under /mnt/c/Users becomes a candidate
//     Windows home (see "Which Windows profiles enumerate" below).
//   - On Windows (any Windows host where \\wsl.localhost\ is enumerable),
//     each <distro>/home/<user> becomes a candidate Linux home.
//   - On macOS / pure Linux / pure Windows, ExtraHomes returns nil.
//
// Each candidate is paired with an OS tag so adapters can produce the
// correct subpaths (e.g. Copilot's per-OS workspaceStorage location)
// without conflating the host runtime's GOOS with the home's logical
// OS. The OS tag is load-bearing, not advisory: a home enumerated here
// with OS=="windows" must be given the WINDOWS shape only. Composing
// the macOS "Library/Application Support" or the XDG ".config" shape
// under it produces a path that cannot exist. Adapters get that right
// for free by resolving their application-data root through
// adapter.AppDataRoots (or the vscodehost / jetbrainshost product
// helpers), which gate every shape on the home's OS.
//
// # Which Windows profiles enumerate
//
// C:\Users holds more than user profiles: the Default / Default User
// templates, the Public shared tree, the All Users junction onto
// ProgramData, and assorted service accounts. wslWindowsHomes drops
// them by name and then requires a real-profile marker (an NTUSER.DAT
// hive or an AppData tree) on whatever survives, de-duplicating
// case-insensitive aliases at the end. windowsprofiles.go owns the
// tables and documents each row.
//
// The filter is a heuristic over an open-ended namespace, so it has an
// escape hatch: set the EnvAllWindowsProfiles environment variable
// (OBSERVER_CROSSMOUNT_ALL_PROFILES) to a truthy value and every
// directory under /mnt/c/Users enumerates again.
//
// # MSIX-packaged Windows apps (Claude Desktop / Cowork)
//
// An MSIX-packaged Windows app redirects its Roaming AppData: what the
// app writes as %APPDATA%\<App> physically lives at
// %LOCALAPPDATA%\Packages\<pkg>\LocalCache\Roaming\<App>, and
// %APPDATA%\<App> is a REPARSE POINT onto it. Two consequences for
// adapters:
//
//   - From a WSL daemon reading a Windows home over DrvFs the reparse
//     point is NOT traversable, so the ONLY reachable spelling is
//     Packages\<pkg>\LocalCache\Roaming\<App>. An adapter that emits
//     just the %APPDATA% spelling captures nothing cross-mount.
//
//   - Windows-native, BOTH spellings resolve to the same directory. An
//     adapter that emits both (which it must, since a non-MSIX install
//     only has the %APPDATA% one) would have its tree walked twice and
//     every session file ingested under two distinct source_file
//     values.
//
// So the rule is: enumerate BOTH candidates per Windows home and rely
// on adapter.DedupRootsByIdentity — applied by the watcher to every
// adapter's roots, and by the adapter itself when its IsSessionFile
// must agree with the watcher's root set — to collapse them on
// Windows-native. Never pick one spelling at discovery time.
package crossmount
