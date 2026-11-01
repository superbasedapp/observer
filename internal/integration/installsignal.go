package integration

// installsignal.go is the install-evidence vocabulary of Capability
// .InstallSignals (WINNODE item 5). The config-home probe (internal/hook
// Registry.Installed) misses a tool that is installed but has not run yet:
// Claude Code as a VS Code extension only, or the agy CLI right after its
// installer. A row names here what else proves the install; the detector
// (cmd/observer installsignal.go) dispatches on the signal's Kind, never on
// the tool.

// InstallSignalKind is the closed set of install evidence.
type InstallSignalKind string

// The InstallSignalKind values.
const (
	// InstallSignalEditorExtension: a directory named
	// "<ExtensionID>-<version>..." in a VS Code-family extensions folder
	// (EditorExtensionDirs).
	InstallSignalEditorExtension InstallSignalKind = "editor_extension"
	// InstallSignalBinary: the row's own Binary resolves (PATH or its probe
	// dirs, so a binary on the registry user Path but not yet on the
	// process PATH counts).
	InstallSignalBinary InstallSignalKind = "binary"
)

// InstallSignal is one piece of install evidence.
type InstallSignal struct {
	Kind InstallSignalKind
	// ExtensionID is the marketplace id (publisher.name), lowercase, for
	// InstallSignalEditorExtension.
	ExtensionID string
}

// EditorExtensionDirs are the per-user extensions folders of the VS
// Code-family editors, home-relative with forward slashes. VS Code's
// documented location is ~/.vscode/extensions (%USERPROFILE%\.vscode\
// extensions on Windows); Insiders, the remote server and the OSS builds use
// their own sibling folders.
var EditorExtensionDirs = []string{
	".vscode/extensions",
	".vscode-insiders/extensions",
	".vscode-server/extensions",
	".vscode-oss/extensions",
}
