// Package zedhost is the Zed editor's host vocabulary, the sibling of
// internal/platform/jetbrainshost for the second ACP host (surface-gap S-1,
// docs/audits/vendor-surface-inventory-2026-10-25.md sections 3.9 and 5).
//
// Zed runs agents two ways: from the ACP registry (an id such as
// "claude-acp", the same ids JetBrains AI Assistant uses) and from a Zed
// EXTENSION that declares its own agent server. An extension's server key is
// chosen by the extension, so it is not a product id: Kilo's Zed extension
// "kilo" names its agent server "opencode" (Kilo-Org/kilocode
// packages/extensions/zed/extension.toml, re-fetched 2026-10-25, inventory
// X13). So an extension agent is keyed by (extension id, server key), never
// by the server key alone, and an unknown pair resolves to no tool.
//
// What it does not do yet: stamp sessions. A Zed surface enricher (the
// jetbrainshost + internal/surfaceenrich shape) needs to know where Zed keeps
// its agent threads and which session id a hosted agent run records, and the
// 2026-10-26 Windows run found no file Zed wrote after an agent chat
// (pending tracker FU-95). Until then this package holds the host token and
// the attribution rule only.
//
// Pure: no I/O at all (pinned by imports_test.go).
package zedhost
