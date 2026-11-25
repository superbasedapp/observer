// Command antigravity-bridge is a Windows-side helper that lets
// observer-on-WSL2 reach Antigravity's local language_server gRPC
// API. The language_server binds to Windows' 127.0.0.1, which is
// not reachable from inside a WSL2 distro under default networking.
// This helper runs as a child process under powershell.exe (which
// lives Windows-side) and bridges the gap.
//
// Invocation contract:
//
//	antigravity-bridge.exe convert <conversation_uuid>
//	antigravity-bridge.exe structured <conversation_uuid>
//	antigravity-bridge.exe probe <method_name> <conversation_uuid> [field_number]
//
// On success: stdout = the response body (Markdown for convert, raw
// gRPC-frame-stripped protobuf for structured/probe), exit code 0.
// On any failure: stderr carries a short error, exit code != 0.
//
// Used by internal/adapter/antigravity when it detects WSL2 +
// Windows-side Antigravity data and `network_recovery = "local"`
// is configured.
package main
