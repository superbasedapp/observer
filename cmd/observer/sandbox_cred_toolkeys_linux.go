//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxkey"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_cred_toolkeys_linux.go is the hosted host helper's half of
// decision SBXD-4 (docs/decisions/sandbox-terminal-decisions-2026-11.md):
// both opt-in per tool, both only under in_box_api_key custody (the plan
// file says so: Create sets ToolKeys and LoginSeed only then), both from
// the tool's grounded registry row, never its name.
//
//   - (b) hostedInBoxToolKeys: the keys the tool saved in its own key file
//     are a third in-box source, after the daemon's environment and the
//     stored keys. The file is read once per run, when the run starts; a key
//     is never logged or said.
//   - (c) seedLoginAccessToken: the tool's login file is written into the box
//     home narrowed to the short-lived access token (never the refresh
//     token), and only while it has not expired.

// hostedToolKeysCache holds each run's saved-key fill (run id -> map), so
// the tool's file is read once per run, not on every agentEnv.
var hostedToolKeysCache sync.Map

// hostedToolKeysHome is the home the tool's own files are read under (a
// test seam).
var hostedToolKeysHome = os.UserHomeDir

// hostedInBoxToolKeys fills, for an in-box run opted in to its tool's own
// saved keys, each provider key variable that the environment and the
// stored keys left empty (a provider whose in-box variables are all unset).
func hostedInBoxToolKeys(plan hostedPlanFile, env map[string]string) {
	if !plan.ToolKeys || vocab.KeyCustody(plan.Custody) != vocab.CustodyInBoxAPIKey {
		return
	}
	for name, val := range hostedToolKeyValues(plan) {
		if env[name] == "" {
			env[name] = val
		}
	}
	// A provider the environment or a stored key already gives keeps it:
	// the fill above only writes empty variables.
}

// hostedToolKeyValues reads the run's tool's own saved keys into the
// variables they fill (name -> key), for the providers the tool can use.
func hostedToolKeyValues(plan hostedPlanFile) map[string]string {
	if v, ok := hostedToolKeysCache.Load(plan.RunID); ok {
		return v.(map[string]string)
	}
	out := map[string]string{}
	row, ok := integration.SandboxSavedKeysFor(plan.Tool)
	rel := row.FileFor(runtime.GOOS)
	if home, err := hostedToolKeysHome(); ok && rel != "" && err == nil {
		if doc, err := hostedReadToolState(home, rel); err == nil {
			fields := make([]sandboxkey.SavedKeyField, 0, len(row.Keys))
			for _, k := range row.Keys {
				fields = append(fields, sandboxkey.SavedKeyField{Provider: k.Provider, Pointer: k.Pointer, TypePointer: k.TypePointer, TypeValue: k.TypeValue})
			}
			usable := sandboxkey.UsableProviders(hostedToolRoute(plan.Tool))
			for id, key := range sandboxkey.SavedKeys(doc, fields, usable) {
				p, ok := sandboxkey.ProviderFor(id)
				if !ok || credEnvSetAny(p.InBoxEnv) {
					continue
				}
				out[p.KeyEnv] = key
			}
		}
	}
	v, _ := hostedToolKeysCache.LoadOrStore(plan.RunID, out)
	return v.(map[string]string)
}

// credEnvSetAny reports whether the daemon's environment sets any of names
// (the first source wins, as for the stored keys).
func credEnvSetAny(names []string) bool {
	for _, n := range names {
		if v, ok := hostedLookupEnv(n); ok && v != "" {
			return true
		}
	}
	return false
}

// hostedLoginSeedMargin is how long before its expiry an access token is no
// longer seeded.
const hostedLoginSeedMargin = time.Minute

// hostedLoginSeedNow is the clock the seed judges expiry by (a test seam).
var hostedLoginSeedNow = time.Now

// hostedLoginSource resolves the tool's login file on this machine
// (agentconfig.ResolveArtifact over the row's Artifact, as sign-in seeding
// does), with no Getenv so the constructor applies the pinned-home rule
// (R-188 F1); ok false when it has no single path.
func hostedLoginSource(home string, row integration.SandboxLoginSeed) (dir, name string, ok bool) {
	dir, name = home, row.File
	if row.Artifact == "" {
		return dir, name, true
	}
	got, err := agentconfig.ResolveArtifact(row.Artifact, agentconfig.PathEnv{GOOS: runtime.GOOS, Home: home})
	if err != nil || got.Status != agentconfig.PathResolved {
		return "", "", false
	}
	p := filepath.Clean(got.Path)
	return filepath.Dir(p), filepath.Base(p), true
}

// seedLoginAccessToken writes the tool's login, narrowed to its access
// token, into the box home (decision SBXD-4 (c)). It is said in the
// terminal whether it was copied and when it expires; never fatal.
func (r *hostedRun) seedLoginAccessToken(ctx context.Context) {
	if !r.plan.LoginSeed || vocab.KeyCustody(r.plan.Custody) != vocab.CustodyInBoxAPIKey {
		return
	}
	row, ok := integration.SandboxLoginSeedFor(r.plan.Tool)
	if !ok || slices.Contains(row.KeychainOn, runtime.GOOS) {
		return
	}
	name := integration.DisplayName(r.plan.Tool)
	home, err := hostedToolKeysHome()
	if err != nil {
		return
	}
	dir, file, ok := hostedLoginSource(home, row)
	if !ok {
		r.say("your %s login was not copied into the box: its file has no single path on this machine", name)
		return
	}
	doc, err := hostedReadToolState(dir, file)
	if err != nil {
		r.say("your %s login was not copied into the box: no login file was found on this machine", name)
		return
	}
	res := sandboxkey.SeedLogin(doc, sandboxkey.LoginSeedSpec{Object: row.Object, Access: row.Access, Expiry: row.Expiry, ExpiryMillis: row.ExpiryMillis, Keep: row.Keep}, hostedLoginSeedNow(), hostedLoginSeedMargin)
	if res.Code != sandboxkey.LoginSeedOK {
		r.say("your %s login was not copied into the box (%s); the agent asks you to sign in there", name, hostedLoginSeedWords[res.Code])
		return
	}
	dst := path.Join(r.layout.Home, row.File)
	if err := r.execOK(ctx, "make the agent's login folder", sandboxremote.ExecSpec{Argv: []string{"mkdir", "-p", "-m", "700", path.Dir(dst)}}); err != nil {
		r.say("your %s login was not copied into the box (%v)", name, err)
		return
	}
	f := sandboxremote.UploadFile{Path: dst, Mode: 0o600, Size: int64(len(res.Doc)), Open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(res.Doc)), nil
	}}
	if err := r.writeFiles(ctx, []sandboxremote.UploadFile{f}); err != nil {
		r.say("your %s login was not copied into the box (%v)", name, err)
		return
	}
	limit := hostedLoginSeedNow().Add(time.Duration(r.plan.TimeoutMinutes) * time.Minute)
	when := res.ExpiresAt.Local().Format("15:04 MST")
	if res.ExpiresAt.Before(limit) {
		r.say("your %s login was copied into the box (its access token only, never the refresh token); it expires at %s, before the box's %d-minute limit, and the agent then asks you to sign in", name, when, r.plan.TimeoutMinutes)
		return
	}
	r.say("your %s login was copied into the box (its access token only, never the refresh token); it expires at %s", name, when)
}

// hostedLoginSeedWords are the plain words for a refused seed.
var hostedLoginSeedWords = map[string]string{
	sandboxkey.LoginSeedUnreadable: "its login file could not be read",
	sandboxkey.LoginSeedNoLogin:    "it is not signed in on this machine",
	sandboxkey.LoginSeedNoExpiry:   "its login does not say when it expires",
	sandboxkey.LoginSeedExpired:    "its login on this machine has expired; sign in again here to refresh it",
}
