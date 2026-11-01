package main

import (
	"fmt"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// initHostGOOS is the OS `observer init` prints shell hints for and decides
// cross-OS bridges on; tests pin it.
var initHostGOOS = runtime.GOOS

// claudeRoutedTo reports whether Claude Code's settings.json (under home,
// "" = the real home) already routes to this node's proxy on port, read
// with a dry-run registration that writes nothing (WINNODE2 16c). Then the
// "point Claude Code at the proxy" hint is noise and is not printed.
func claudeRoutedTo(home string, port int) bool {
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: port, HomeDir: home, DryRun: true})
	if err != nil {
		return false
	}
	res := reg.RegisterClaudeCode()
	return res.Error == nil && res.AlreadySet && res.BaseURL == fmt.Sprintf("http://127.0.0.1:%d", port)
}

// windowsBridgeBrowserHomes picks the Windows homes the browser step offers
// the wsl.exe bridge for: the cross-mounted Windows profiles a Linux (WSL)
// daemon sees. A native Windows daemon builds no bridge (its browsers are
// wired natively), so there it returns none, and `observer init --all` no
// longer prints the "WSL distro is unknown" lines on native Windows
// (WINNODE2 16c).
func windowsBridgeBrowserHomes(goos string, all []crossmount.HomeRoot) []string {
	if goos == "windows" {
		return nil
	}
	var homes []string
	for _, h := range all {
		if h.OS == crossmount.OSWindows {
			homes = append(homes, h.Path)
		}
	}
	return homes
}
