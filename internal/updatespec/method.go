package updatespec

// Method is how the running binary got onto this machine. It decides
// whether the node may replace itself at all (§3.7 install-method
// table, ruling R6).
type Method string

const (
	// MethodBinary is a standalone binary this uid can replace - the
	// only self-applying method.
	MethodBinary Method = "binary"
	// MethodBinaryReadOnly is a standalone binary this uid may NOT
	// replace (a root-owned /usr/local/bin install run as a user).
	MethodBinaryReadOnly Method = "binary_readonly"
	// MethodNPM is an npm-owned install (@superbased/observer plus a
	// platform package).
	MethodNPM Method = "npm"
	// MethodPip is a PyPI/venv-owned install (superbased-observer).
	MethodPip Method = "pip"
	// MethodVSCode is the copy the VS Code extension manages.
	MethodVSCode Method = "vscode"
	// MethodBrew is a Homebrew/Linuxbrew Cellar install.
	MethodBrew Method = "brew"
	// MethodAPT is a dpkg-owned install.
	MethodAPT Method = "apt"
	// MethodRPM is an rpm-owned install.
	MethodRPM Method = "rpm"
	// MethodInstaller is a copy the Windows setup program installed (it
	// owns the files, the Start menu entry and the Apps and Features
	// entry). It upgrades by running the newer setup program, never by
	// replacing its own binary.
	MethodInstaller Method = "installer"
	// MethodUnknown is the honest zero value: nothing was resolvable
	// (no executable path). It never self-applies.
	MethodUnknown Method = "unknown"
)
