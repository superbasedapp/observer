package winshim

// Launch is how an AI client process starts a stdio MCP server command on
// native Windows. It is a property of the CLIENT (how its process spawner
// resolves a bare name), not of the command, so the client's registry row
// carries it and a config writer passes it in here.
//
// The zero value LaunchAsIs means "no grounded Windows launch behaviour":
// the command is written exactly as given, the honest default for a client
// nobody has checked.
type Launch int

const (
	// LaunchAsIs writes the command unchanged.
	LaunchAsIs Launch = iota
	// LaunchCmdExtension names an npm shim by its `.cmd` file (`npx.cmd`).
	// For a client that starts the program directly without trying
	// %PATHEXT%, so a bare `npx` is not found, but that can start a `.cmd`
	// it is given by name (a Rust std::process::Command spawner).
	LaunchCmdExtension
	// LaunchCmdShell runs an npm shim through the command interpreter
	// (`cmd /c npx ...`). For a client whose spawner can start neither a
	// bare `npx` nor `npx.cmd` (a Node child_process spawn without a shell,
	// which refuses a batch file), so only an `.exe` reaches the shim.
	LaunchCmdShell
)

// StdioLaunch returns command and args in the form a client with launch
// behaviour how starts on goos. Only a bare `npm` or `npx` command changes,
// and only on Windows; an absolute path, an `.exe`, and every command on
// any other OS come back as given. The returned args slice is always a
// fresh copy, so a caller may keep the input.
func StdioLaunch(command string, args []string, goos string, how Launch) (string, []string) {
	out := append([]string(nil), args...)
	if goos != "windows" {
		return command, out
	}
	cmd, ok := shimFor(command)
	if !ok {
		return command, out
	}
	switch how {
	case LaunchCmdExtension:
		return cmd, out
	case LaunchCmdShell:
		return "cmd", append([]string{"/c", command}, out...)
	default:
		return command, out
	}
}

// shimFor reports the `.cmd` form of a bare npm shim name.
func shimFor(command string) (string, bool) {
	for _, s := range cmdShims {
		if command == s.bare {
			return s.cmd, true
		}
	}
	return "", false
}
