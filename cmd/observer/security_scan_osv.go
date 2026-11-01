//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_osv

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvscanner"
)

// security_scan_osv.go wires the osv-scanner subprocess driver
// (security.scan.osv): the canary project it scans beside the real one,
// and the guided vendor install offer. Nothing here installs anything.

// depsOSVDriver returns the driver; the canary project and Observer's empty
// osv-scanner config are written under canaryDir first.
func depsOSVDriver(runner *extrun.Runner, dbDir string, epochs map[string]string, canaryDir string) secscan.Driver {
	// A canary that could not be written fails every ecosystem's
	// self-test: "not scanned", never clean, so the error needs no path of
	// its own.
	_ = writeOSVCanary(canaryDir)
	return osvscanner.New(osvscanner.Env{
		Runner: runner, DBDir: dbDir, Epochs: epochs, CanaryDir: canaryDir,
		HomeDir: filepath.Join(filepath.Dir(canaryDir), "osv-scanner-home"),
		GOOS:    runtime.GOOS, GOARCH: runtime.GOARCH,
	})
}

// writeOSVCanary writes depscan.CanaryFiles and the empty config.
func writeOSVCanary(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := depscan.CanaryFiles()
	files[osvscanner.ConfigFile] = "# Observer's own osv-scanner config: empty, so a repository's osv-scanner.toml is never read.\n"
	for name, body := range files {
		p := filepath.Join(dir, name)
		if b, err := os.ReadFile(p); err == nil && string(b) == body {
			continue
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// osvInstallOffer is the guided vendor install text (D-766): the vendor's
// own channels, shown for the user to run. Observer runs none of them.
const osvInstallOffer = `osv-scanner is not bundled with Observer. To use the security.scan.osv driver, install it
yourself from the vendor (https://google.github.io/osv-scanner/installation/), for example:

  go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.6.0
  brew install osv-scanner                      (macOS or Linux with Homebrew)
  a release binary from https://github.com/google/osv-scanner/releases/tag/v2.6.0
    (check it against the release's osv-scanner_SHA256SUMS; linux amd64 sha256 %s)

Observer installs nothing by itself. Until osv-scanner is on this machine, the driver starts no
process and every project's dependencies show as "not scanned".
`

func newSecurityScanInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-osv-scanner",
		Short: "Show how to install osv-scanner for the security.scan.osv driver (installs nothing)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), osvInstallOffer, depscan.OSVScannerLinuxAMD64)
			return nil
		},
	}
}
