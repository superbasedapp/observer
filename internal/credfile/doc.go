// Package credfile holds the byte-level editors behind the D-268/D-270
// credential-file exception: the rules a writer follows when it must
// read-modify-write a vendor config file that also holds plaintext
// credentials (a provider key, a bearer token, a sibling MCP server's env
// block).
//
// The rules (the hook writers in internal/hook/credentialfile.go and the
// MCP registrars in internal/mcp both apply them, review T-384):
//
//   - Only a registry row that declares the file may write it
//     (integration.HookSpec.HooksShareCredentialFile for a hook writer,
//     integration.MCPTarget.SharesCredentialFile for an MCP writer,
//     integration.ProxyRoute.SharesCredentialFile for a route writer).
//   - Only the span Observer owns is edited: every other member keeps its
//     bytes and its position (JSON is spliced member by member, TOML is
//     edited line by line, and SetMember / SetYAMLMember edit one member of
//     a YAML, JSON or TOML file through the order-preserving cfgfmt engine),
//     and the result is decoded and compared value for value against the
//     intended document before anything is written.
//   - The file's permission bits are kept.
//   - No whole-file hash and no value read from the file is stored or
//     surfaced: an error a decoder produced is withheld (decoders quote the
//     input), and messages name only paths, keys and event names.
//
// The package does no I/O: it takes bytes and returns bytes; the callers
// own the reads, the writes and the registry lookups.
package credfile
