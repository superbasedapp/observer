//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// sandbox_native_forced.go reads what a host says about an agent's own
// sandbox (sandbox plan v2 section 4.4, D-746 Q17, lane SBX-P3D): whether a
// vendor managed policy forces it on (vendor_forced_native) and whether the
// user turned an off-by-default sandbox on (weak mode). It reads only the
// files a row of internal/integration's side table names (the vendor's
// documented paths), locally, never following a symlink, capped in size,
// and only the boolean keys the row lists. A row with no probe is never
// detected: the run behaves as before and the vendor's own refusal stays
// loud.

// nativeSettingMaxBytes caps a settings file read.
const nativeSettingMaxBytes = 1 << 20

// nativeHostFacts are what Observer read about a tool's own sandbox.
type nativeHostFacts struct {
	forced bool
	userOn bool
	policy string
}

// nativeReadSetting reads a settings file: a regular file (a symlink or
// anything else is not read), at most nativeSettingMaxBytes. A test
// replaces it.
var nativeReadSetting = func(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > nativeSettingMaxBytes {
		return nil, errors.New("not a regular file within its cap")
	}
	f, err := os.Open(path) //nolint:gosec // a vendor-documented settings path from the side table
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, nativeSettingMaxBytes))
}

// nativeHome and nativeGOOS are the host's facts (test seams).
var (
	nativeHome = os.UserHomeDir
	nativeGOOS = runtime.GOOS
)

// nativeSettingTrue reports whether the probe's condition holds on this
// host: every key it names is the boolean true in the merged settings (the
// documents are the file and then its drop-ins in sorted name order, the
// order Claude Code merges them, and for each key the last document that
// sets it wins: an earlier false is overridden by a later true and the
// other way round; the LEFT-SBX merge, audit finding 7), or, for a
// LacksValue probe, the named list exists and does not hold the value. Anything else (no file, unreadable, not the format, a
// key missing, an ungrounded probe) is false.
func nativeSettingTrue(p integration.NativeSettingProbe) bool {
	if !p.Grounded() {
		return false
	}
	docs := nativeSettingDocs(p)
	if len(docs) == 0 {
		return false
	}
	if p.LacksValue != "" {
		for _, doc := range docs {
			list, ok := nativeKeyValue(doc, p.Keys[0]).([]any)
			if !ok {
				continue
			}
			for _, v := range list {
				if s, _ := v.(string); s == p.LacksValue {
					return false
				}
			}
			return true
		}
		return false
	}
	for _, key := range p.Keys {
		var last any
		for _, doc := range docs {
			if v := nativeKeyValue(doc, key); v != nil {
				last = v
			}
		}
		if b, ok := last.(bool); !ok || !b {
			return false
		}
	}
	return true
}

// nativeMaxDropIns caps how many drop-in files one probe reads.
const nativeMaxDropIns = 64

// nativeSettingDocs reads the probe's documents in merge order: its file
// and, when it names a drop-in directory, each regular *.json file in it
// (sorted by name, capped, never through a symlink), decoded in the probe's
// format. A document that
// does not decode is left out.
func nativeSettingDocs(p integration.NativeSettingProbe) []map[string]any {
	expand := func(path string) string {
		if rest, ok := strings.CutPrefix(path, "~/"); ok {
			home, err := nativeHome()
			if err != nil || home == "" {
				return ""
			}
			return filepath.Join(home, rest)
		}
		return path
	}
	var paths []string
	if f := expand(p.PathFor(nativeGOOS)); f != "" {
		paths = append(paths, f)
	}
	if d := p.DropIns[nativeGOOS]; d != "" {
		if dir := expand(d); dir != "" {
			if fi, err := os.Lstat(dir); err == nil && fi.IsDir() {
				if entries, err := os.ReadDir(dir); err == nil {
					n := 0
					for _, e := range entries {
						if n >= nativeMaxDropIns {
							break
						}
						if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json") {
							paths = append(paths, filepath.Join(dir, e.Name()))
							n++
						}
					}
				}
			}
		}
	}
	var docs []map[string]any
	for _, path := range paths {
		b, err := nativeReadSetting(path)
		if err != nil {
			continue
		}
		var doc map[string]any
		switch p.Format {
		case "toml":
			err = toml.Unmarshal(b, &doc)
		default:
			err = json.Unmarshal(b, &doc)
		}
		if err == nil && doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs
}

// nativeKeyValue is the value at key in doc (nil when any step is missing
// or not an object).
func nativeKeyValue(doc map[string]any, key []string) any {
	var cur any = doc
	for _, k := range key {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

// nativeFactsFor reads a row's probes: the managed-policy files always (a
// row lists them only where the vendor documents them), the user's own
// setting only for a row with a per-run weak mode.
var nativeFactsFor = func(n integration.NativeSandbox) nativeHostFacts {
	var f nativeHostFacts
	for _, m := range n.Managed {
		if nativeSettingTrue(m) {
			f.forced = true
			break
		}
	}
	if n.UserOn != nil && n.WeakMode.PerRun() {
		f.userOn = nativeSettingTrue(*n.UserOn)
	}
	if f.forced {
		f.policy = vendorForcedPolicy()
	}
	return f
}

// vendorForcedPolicy is the effective [terminal.sandbox].vendor_forced_native
// of the daemon's config (an org pin applied), nest_or_refuse when it cannot
// be read. Read only when a forced sandbox was detected; both values refuse
// a conflict today, so it changes the refusal's words, not the answer.
var vendorForcedPolicy = func() string {
	path, err := config.ResolveGlobalPath(daemonConfigPath())
	if err == nil {
		if cfg, lerr := config.Load(config.LoadOptions{GlobalPath: path}); lerr == nil {
			if v := effectiveSandboxConfig(cfg).VendorForcedNative; v == sandboxselect.VendorForcedRefuse {
				return v
			}
		}
	}
	return sandboxselect.VendorForcedNestOrRefuse
}
