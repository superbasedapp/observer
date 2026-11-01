package winshim

import "strings"

// cmdShims lists the npm-installed launchers whose bare name PowerShell
// resolves to a `.ps1` script. A row is the bare first word and the `.cmd`
// form that replaces it on Windows.
var cmdShims = []struct {
	bare string
	cmd  string
}{
	{bare: "npm", cmd: "npm.cmd"},
	{bare: "npx", cmd: "npx.cmd"},
}

// CommandFor returns command as a user on goos should type it. On Windows a
// command whose first word is a bare `npm` or `npx` gets the `.cmd` form;
// every other command, and every command on any other OS, is returned
// unchanged.
func CommandFor(command, goos string) string {
	if goos != "windows" {
		return command
	}
	for _, s := range cmdShims {
		if command == s.bare {
			return s.cmd
		}
		if rest, ok := strings.CutPrefix(command, s.bare+" "); ok {
			return s.cmd + " " + rest
		}
	}
	return command
}
