//go:build !sbo_omit_ingest_otlp

package clientwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/telemetrywire"
)

// telemetry_wire.go is the exporter-config writer, owned by the ingest.otlp
// component (telemetry_omit.go is the off side).

// TelemetrySupported reports whether Observer can point tool's own OTLP
// exporter at the node: the registry row declares an exporter-config writer
// (integration.OTLPWire), the export is one the node maps, and it is sent
// from the developer's machine (a vendor-cloud export can never reach a
// node). The cross-OS "-windows" target is not offered: the receiver is
// the daemon's loopback.
func TelemetrySupported(tool string) bool {
	c, isWindows, ok := AdvertisedCapability(tool)
	if !ok || isWindows {
		return false
	}
	return c.OTLP.Wire.Kind != integration.OTLPWireNone && c.OTLP.Mapped && c.OTLP.Origin == integration.OTLPLocal
}

// telemetryOwnershipSuffix names the ownership record kept beside a tool's
// exporter config file: the exact endpoint Observer installed there. It is
// what a later status, port change or removal compares against (P3-12), so a
// loopback endpoint the user configured for their own collector is never
// taken for Observer's. It lives OUTSIDE the vendor file, records only
// Observer's own value (never a value read from the file) and holds no
// credential.
const telemetryOwnershipSuffix = ".observer-otlp-export.json"

type telemetryOwnership struct {
	Endpoint string `json:"endpoint"`
}

func telemetryOwnershipPath(configPath string) string { return configPath + telemetryOwnershipSuffix }

// readTelemetryOwnership returns the recorded endpoint ("" when none or
// unreadable: no record owns nothing).
func readTelemetryOwnership(configPath string) string {
	raw, err := os.ReadFile(telemetryOwnershipPath(configPath)) //nolint:gosec // Observer's own record beside the registry path
	if err != nil {
		return ""
	}
	var o telemetryOwnership
	if json.Unmarshal(raw, &o) != nil {
		return ""
	}
	return o.Endpoint
}

func writeTelemetryOwnership(configPath, endpoint string) error {
	raw, err := json.Marshal(telemetryOwnership{Endpoint: endpoint})
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(telemetryOwnershipPath(configPath), append(raw, '\n'), fsatomic.Options{FilePerm: 0o600, DirPerm: 0o700})
}

// TelemetryConfigPath resolves the exporter config file for tool.
func TelemetryConfigPath(tool string, opts TelemetryOptions) (string, error) {
	c, _, ok := AdvertisedCapability(tool)
	if !ok || c.OTLP.Wire.Kind == integration.OTLPWireNone {
		return "", fmt.Errorf("clientwire: no exporter config writer for %q", tool)
	}
	w := c.OTLP.Wire
	if opts.HomeDir == "" && w.DirEnv != "" {
		if dir := crossmount.HomeEnv("", opts.Getenv)(w.DirEnv); dir != "" {
			return filepath.Join(dir, filepath.Base(w.File)), nil
		}
	}
	home := opts.HomeDir
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("clientwire: home dir: %w", err)
		}
		home = h
	}
	return filepath.Join(home, filepath.FromSlash(w.File)), nil
}

// TelemetryWired reports whether tool's exporter config currently carries
// Observer's wiring (a read; never writes).
func TelemetryWired(tool string, opts TelemetryOptions) bool {
	c, _, ok := AdvertisedCapability(tool)
	if !ok {
		return false
	}
	path, err := TelemetryConfigPath(tool, opts)
	if err != nil {
		return false
	}
	content, err := os.ReadFile(path) //nolint:gosec // the tool's own config path from the registry
	if err != nil {
		return false
	}
	return telemetrywire.Wired(c.OTLP.Wire.Kind, content, readTelemetryOwnership(path))
}

// WireTelemetry applies (OpApply) or removes (OpRemove) Observer's exporter
// wiring in tool's config file. It is the ONE writer of that edit: it takes
// the shared settings-file lock (the hook registry's, so it serializes
// against hook registration of the same file), keeps the file's mode, writes
// atomically, and writes nothing when the edit changes nothing (an
// unchanged file is never rewritten) or when it would overwrite a setting
// the user made (Conflict).
func WireTelemetry(tool string, op telemetrywire.Op, opts TelemetryOptions) TelemetryResult {
	res := TelemetryResult{Tool: tool, DryRun: opts.DryRun}
	if !TelemetrySupported(tool) {
		res.Error = fmt.Errorf("clientwire: Observer does not wire %s's OpenTelemetry export", tool)
		return res
	}
	c, _, _ := AdvertisedCapability(tool)
	path, err := TelemetryConfigPath(tool, opts)
	if err != nil {
		res.Error = err
		return res
	}
	res.ConfigPath = path
	addr := "127.0.0.1:0" // a removal does not use the address
	if op == telemetrywire.OpApply {
		if opts.ReceiverRequiresToken {
			res.Error = ErrReceiverRequiresToken
			return res
		}
		if addr, err = telemetrywire.ReceiverAddr(opts.Addr); err != nil {
			res.Error = err
			return res
		}
	}
	if !opts.DryRun {
		lock := hook.LockSettingsFile
		if op != telemetrywire.OpApply {
			// A removal never creates a missing vendor directory (T-742).
			lock = hook.LockSettingsFileIfPresent
		}
		release, lerr := lock(path)
		if lerr != nil {
			res.Error = lerr
			return res
		}
		defer release()
	}
	content, mode, err := readConfig(path)
	if err != nil {
		res.Error = err
		return res
	}
	owned := readTelemetryOwnership(path)
	plan, err := telemetrywire.Plan(c.OTLP.Wire.Kind, op, content, addr, owned)
	if err != nil {
		// Never wrap the file's bytes into the error: only the reason.
		res.Error = fmt.Errorf("clientwire: %s: %w", path, err)
		return res
	}
	// The record after this call: an apply owns the endpoint it wanted; a
	// removal that took Observer's wiring out owns nothing any more.
	after := owned
	switch {
	case plan.Conflict != "":
	case op == telemetrywire.OpApply:
		after = telemetrywire.Endpoint(addr)
	case plan.Changed:
		after = ""
	}
	res.Conflict, res.Summary, res.Changed = plan.Conflict, plan.Summary, plan.Changed
	res.Wired = telemetrywire.Wired(c.OTLP.Wire.Kind, plan.Content, after)
	if opts.DryRun || plan.Conflict != "" {
		return res
	}
	if plan.Changed {
		if err := fsatomic.WriteFile(path, plan.Content, fsatomic.Options{FilePerm: mode, DirPerm: 0o700}); err != nil {
			res.Error = err
			return res
		}
	}
	// Record ownership only after the vendor file holds it, so a failed write
	// never leaves a record claiming a value Observer did not install.
	if after != owned {
		if after == "" {
			err = os.Remove(telemetryOwnershipPath(path))
			if errors.Is(err, fs.ErrNotExist) {
				err = nil
			}
		} else {
			err = writeTelemetryOwnership(path, after)
		}
		if err != nil {
			res.Error = fmt.Errorf("clientwire: ownership record for %s: %w", path, err)
		}
	}
	return res
}

// readConfig reads a config file and its mode; a missing file reads as
// empty with mode 0600 (the mode a newly created file gets).
func readConfig(path string) ([]byte, os.FileMode, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0o600, nil
	}
	if err != nil {
		return nil, 0, err
	}
	content, err := os.ReadFile(path) //nolint:gosec // the tool's own config path from the registry
	if err != nil {
		return nil, 0, err
	}
	return content, info.Mode().Perm(), nil
}

// removeTelemetry takes Observer's exporter wiring out of tool's config file
// (the Remover's PartTelemetry step).
func removeTelemetry(tool string, opts TelemetryOptions) TelemetryResult {
	return WireTelemetry(tool, telemetrywire.OpRemove, opts)
}
