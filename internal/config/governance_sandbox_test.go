package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
)

// TestGovernanceSandboxPins walks the [terminal.sandbox] pin rows (lane
// SBX-P1B, sandbox plan v2 section 10.1) through the overlay: each list
// operator, the retention comparator and the restrictive-only rows.
func TestGovernanceSandboxPins(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(c *Config)
		pins    map[string]any
		check   func(c Config) any
		want    any
		skipped bool
	}{
		{
			name:  "ordered filter applies to the legacy backend when backends is empty",
			setup: func(c *Config) { c.Terminal.Sandbox.Backend = "bwrap" },
			pins:  map[string]any{"terminal.sandbox.backends": []any{"bwrap", "oci-runc"}},
			check: func(c Config) any { return c.Terminal.Sandbox.Backends },
			want:  []string{"bwrap"},
		},
		{
			name:  "ordered filter removing every entry enables no backend, never the default or the node's own",
			setup: func(c *Config) { c.Terminal.Sandbox.Backends = []string{"bwrap"} },
			pins:  map[string]any{"terminal.sandbox.backends": []any{"oci-runc"}},
			check: func(c Config) any {
				return []any{len(c.Terminal.Sandbox.Backends), c.Terminal.Sandbox.PinnedNoBackend, len(SandboxEffectiveBackends(&c))}
			},
			want: []any{0, "terminal.sandbox.backends", 0},
		},
		{
			name:  "ordered filter keeps the local order",
			setup: func(c *Config) { c.Terminal.Sandbox.Backends = []string{"oci-runsc", "bwrap", "oci-runc"} },
			pins:  map[string]any{"terminal.sandbox.backends": []any{"bwrap", "oci-runsc"}},
			check: func(c Config) any { return c.Terminal.Sandbox.Backends },
			want:  []string{"oci-runsc", "bwrap"},
		},
		{
			name:  "an empty local host list reads any while no pin is in force",
			pins:  map[string]any{"terminal.sandbox.remote_allowed_hosts": []any{"github.com"}},
			check: func(c Config) any { return c.Terminal.Sandbox.RemoteAllowedHosts },
			want:  []string{"github.com"},
		},
		{
			name: "a disjoint host list allows no host: remote clone off, the list never widened",
			setup: func(c *Config) {
				c.Terminal.Sandbox.RemoteAllowedHosts = []string{"gitlab.example"}
				c.Terminal.Sandbox.AllowRemoteClone = true
			},
			pins: map[string]any{"terminal.sandbox.remote_allowed_hosts": []any{"github.com"}},
			check: func(c Config) any {
				return []any{c.Terminal.Sandbox.AllowRemoteClone, c.Terminal.Sandbox.RemoteAllowedHosts}
			},
			want: []any{false, []string{"gitlab.example"}},
		},
		{
			name:  "install scripts: an org pin holds the node to none (lane LEFT-SBX)",
			pins:  map[string]any{"terminal.sandbox.oci.install_scripts": "none"},
			check: func(c Config) any { return c.Terminal.Sandbox.OCI.InstallScripts },
			want:  "none",
		},
		{
			name:    "install scripts: a pin can never raise none to pinned",
			setup:   func(c *Config) { c.Terminal.Sandbox.OCI.InstallScripts = "none" },
			pins:    map[string]any{"terminal.sandbox.oci.install_scripts": "pinned"},
			check:   func(c Config) any { return c.Terminal.Sandbox.OCI.InstallScripts },
			want:    "none",
			skipped: true,
		},
		{
			name:  "agent-run hosts: an empty node list takes the org's (lane LEFT-SBX)",
			pins:  map[string]any{"terminal.sandbox.egress_allow_hosts": []any{"registry.npmjs.org", "*.github.com"}},
			check: func(c Config) any { return c.Terminal.Sandbox.EgressAllowHosts },
			want:  []string{"*.github.com", "registry.npmjs.org"},
		},
		{
			name:  "agent-run hosts: an org list narrows the node's",
			setup: func(c *Config) { c.Terminal.Sandbox.EgressAllowHosts = []string{"pypi.org", "registry.npmjs.org"} },
			pins:  map[string]any{"terminal.sandbox.egress_allow_hosts": []any{"registry.npmjs.org"}},
			check: func(c Config) any { return c.Terminal.Sandbox.EgressAllowHosts },
			want:  []string{"registry.npmjs.org"},
		},
		{
			name:  "agent-run hosts: nothing in common allows no host, never the tier's own",
			setup: func(c *Config) { c.Terminal.Sandbox.EgressAllowHosts = []string{"pypi.org"} },
			pins:  map[string]any{"terminal.sandbox.egress_allow_hosts": []any{"registry.npmjs.org"}},
			check: func(c Config) any {
				return []any{len(c.Terminal.Sandbox.EgressAllowHosts), c.Terminal.Sandbox.PinnedNoEgressHost}
			},
			want: []any{0, "terminal.sandbox.egress_allow_hosts"},
		},
		{
			name:  "masks are added",
			setup: func(c *Config) { c.Terminal.Sandbox.MaskPaths = []string{"/a"} },
			pins:  map[string]any{"terminal.sandbox.mask_paths": []any{"/b"}},
			check: func(c Config) any { return c.Terminal.Sandbox.MaskPaths },
			want:  []string{"/a", "/b"},
		},
		{
			name:  "retention: forever survives a finite pin",
			pins:  map[string]any{"terminal.sandbox.workspace_retention_days": float64(30)},
			check: func(c Config) any { return c.Terminal.Sandbox.WorkspaceRetentionDays },
			want:  0,
		},
		{
			name:  "retention: a pin lengthens",
			setup: func(c *Config) { c.Terminal.Sandbox.WorkspaceRetentionDays = 7 },
			pins:  map[string]any{"terminal.sandbox.workspace_retention_days": float64(30)},
			check: func(c Config) any { return c.Terminal.Sandbox.WorkspaceRetentionDays },
			want:  30,
		},
		{
			name:  "retention: a pin never shortens",
			setup: func(c *Config) { c.Terminal.Sandbox.WorkspaceRetentionDays = 90 },
			pins:  map[string]any{"terminal.sandbox.workspace_retention_days": float64(30)},
			check: func(c Config) any { return c.Terminal.Sandbox.WorkspaceRetentionDays },
			want:  90,
		},
		{
			name:  "rw binds may be emptied",
			setup: func(c *Config) { c.Terminal.Sandbox.ExtraRWBinds = []string{"/srv"} },
			pins:  map[string]any{"terminal.sandbox.extra_rw_binds": []any{}},
			check: func(c Config) any { return len(c.Terminal.Sandbox.ExtraRWBinds) },
			want:  0,
		},
		{
			name:    "rw binds may never be set",
			pins:    map[string]any{"terminal.sandbox.extra_rw_binds": []any{"/srv"}},
			check:   func(c Config) any { return len(c.Terminal.Sandbox.ExtraRWBinds) },
			want:    0,
			skipped: true,
		},
		{
			name:    "remote clone may never be turned on",
			pins:    map[string]any{"terminal.sandbox.allow_remote_clone": true},
			check:   func(c Config) any { return c.Terminal.Sandbox.AllowRemoteClone },
			want:    false,
			skipped: true,
		},
		{
			name:  "mxc tier: an org pin holds the node on ProcessContainer (R-034)",
			pins:  map[string]any{"terminal.sandbox.windows.mxc_tier": "process_container"},
			check: func(c Config) any { return c.Terminal.Sandbox.Windows.MXCTier },
			want:  "process_container",
		},
		{
			name:    "mxc tier: a pin can never move a node onto AppContainer (R-034)",
			setup:   func(c *Config) { c.Terminal.Sandbox.Windows.MXCTier = "process_container" },
			pins:    map[string]any{"terminal.sandbox.windows.mxc_tier": "appcontainer"},
			check:   func(c Config) any { return c.Terminal.Sandbox.Windows.MXCTier },
			want:    "process_container",
			skipped: true,
		},
		{
			name:  "readopt bound: an org pin shortens it (R-034)",
			setup: func(c *Config) { c.Terminal.Sandbox.Readopt.BoundMinutes = 60 },
			pins:  map[string]any{"terminal.sandbox.readopt.bound_minutes": float64(5)},
			check: func(c Config) any { return c.Terminal.Sandbox.Readopt.BoundMinutes },
			want:  5,
		},
		{
			name:  "readopt bound: a pin can never lengthen it (R-034)",
			setup: func(c *Config) { c.Terminal.Sandbox.Readopt.BoundMinutes = 5 },
			pins:  map[string]any{"terminal.sandbox.readopt.bound_minutes": float64(60)},
			check: func(c Config) any { return c.Terminal.Sandbox.Readopt.BoundMinutes },
			want:  5,
		},
		{
			// LEFT2 audit S1: a node on the default (0, read as 10 minutes)
			// is never lengthened by a ceiling pin above the default.
			name:  "readopt bound: a pin above the default never lengthens a defaulted node",
			pins:  map[string]any{"terminal.sandbox.readopt.bound_minutes": float64(1440)},
			check: func(c Config) any { return c.Terminal.Sandbox.Readopt.BoundMinutes },
			want:  SandboxReadoptDefaultBoundMinutes,
		},
		{
			name:  "readopt bound: a pin below the default shortens a defaulted node",
			pins:  map[string]any{"terminal.sandbox.readopt.bound_minutes": float64(5)},
			check: func(c Config) any { return c.Terminal.Sandbox.Readopt.BoundMinutes },
			want:  5,
		},
		{
			// LEFT2 audit S1: 0 is 2048 MiB, so a pin of 1048576 must not raise it.
			name:  "readopt checkpoint cap: a pin above the default never raises a defaulted node",
			pins:  map[string]any{"terminal.sandbox.readopt.checkpoint_cap_mib": float64(1 << 20)},
			check: func(c Config) any { return c.Terminal.Sandbox.Readopt.CheckpointCapMiB },
			want:  SandboxReadoptDefaultCheckpointCapMiB,
		},
		{
			name:  "readopt checkpoint cap: a pin below the default shrinks a defaulted node",
			pins:  map[string]any{"terminal.sandbox.readopt.checkpoint_cap_mib": float64(512)},
			check: func(c Config) any { return c.Terminal.Sandbox.Readopt.CheckpointCapMiB },
			want:  512,
		},
		{
			name:  "readopt checkpoint cap: an org pin shrinks it (R-034)",
			setup: func(c *Config) { c.Terminal.Sandbox.Readopt.CheckpointCapMiB = 2048 },
			pins:  map[string]any{"terminal.sandbox.readopt.checkpoint_cap_mib": float64(512)},
			check: func(c Config) any { return c.Terminal.Sandbox.Readopt.CheckpointCapMiB },
			want:  512,
		},
		{
			name:    "home mode may never be readonly",
			pins:    map[string]any{"terminal.sandbox.home_mode": "readonly"},
			check:   func(c Config) any { return c.Terminal.Sandbox.HomeMode },
			want:    Default().Terminal.Sandbox.HomeMode,
			skipped: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			if tc.setup != nil {
				tc.setup(&cfg)
			}
			got, out := ApplyGovernancePinsTo(cfg, tc.pins)
			if v := tc.check(got); !reflect.DeepEqual(v, tc.want) {
				t.Fatalf("value = %#v, want %#v (skipped %v)", v, tc.want, out.Skipped)
			}
			if (len(out.Skipped) > 0) != tc.skipped {
				t.Fatalf("skipped = %v, want skipped=%v", out.Skipped, tc.skipped)
			}
		})
	}
}

// TestApplyGovernancePinsToCopies: the posture check's overlay never changes
// the config it was given.
func TestApplyGovernancePinsToCopies(t *testing.T) {
	cfg := Default()
	cfg.Terminal.Sandbox.MaskPaths = []string{"/a"}
	_, _ = ApplyGovernancePinsTo(cfg, map[string]any{"terminal.sandbox.mask_paths": []any{"/b"}})
	if !reflect.DeepEqual(cfg.Terminal.Sandbox.MaskPaths, []string{"/a"}) {
		t.Fatalf("the caller's config changed: %v", cfg.Terminal.Sandbox.MaskPaths)
	}
}

// TestGovernanceSandboxEmptiedPinsOnEveryLoad is SBX-P1B merge audit finding
// 2 through the real loader: a pin accepted while it overlapped the node's
// own list keeps its meaning after the developer edits that list to
// something disjoint. An emptied backend filter enables no backend and an
// empty host intersection turns remote clones off, on the next Load, never
// falling back to the developer's own list.
func TestGovernanceSandboxEmptiedPinsOnEveryLoad(t *testing.T) {
	dbDir := t.TempDir()
	sidecar := `{"schema":1,"state":"applied","pinned":{` +
		`"terminal.sandbox.backends":["bwrap"],` +
		`"terminal.sandbox.remote_allowed_hosts":["github.com"]}}`
	govWriteSidecar(t, dbDir, sidecar)
	accepted := govTempConfig(t, dbDir, `[terminal.sandbox]
enabled = true
backends = ["bwrap"]
allow_remote_clone = true
remote_allowed_hosts = ["github.com", "gitlab.example"]
`)
	cfg, err := Load(LoadOptions{GlobalPath: accepted, Env: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ts := cfg.Terminal.Sandbox
	if !reflect.DeepEqual(ts.Backends, []string{"bwrap"}) || ts.PinnedNoBackend != "" ||
		!ts.AllowRemoteClone || !reflect.DeepEqual(ts.RemoteAllowedHosts, []string{"github.com"}) {
		t.Fatalf("at accept: %+v", ts)
	}

	// The developer edits their own lists after the pin was accepted.
	edited := govTempConfig(t, dbDir, `[terminal.sandbox]
enabled = true
backends = ["oci-runc"]
allow_remote_clone = true
remote_allowed_hosts = ["gitlab.example"]
`)
	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: edited, Env: noEnv})
	if err != nil {
		t.Fatalf("LoadGovernance: %v", err)
	}
	ts = cfg.Terminal.Sandbox
	if len(ts.Backends) != 0 || ts.PinnedNoBackend != "terminal.sandbox.backends" || len(SandboxEffectiveBackends(&cfg)) != 0 {
		t.Fatalf("an emptied backend filter fell back to a backend: %+v", ts)
	}
	if ts.AllowRemoteClone {
		t.Fatalf("an empty host intersection left remote clones on: %+v", ts)
	}
	for _, k := range []string{"terminal.sandbox.backends", "terminal.sandbox.remote_allowed_hosts", "terminal.sandbox.allow_remote_clone"} {
		found := false
		for _, a := range out.Applied {
			found = found || a == k
		}
		if !found {
			t.Errorf("%s not reported as set by the organization: %v", k, out.Applied)
		}
	}
	for k := range out.Skipped {
		if strings.HasPrefix(k, "terminal.sandbox.") {
			t.Errorf("sandbox pin %s skipped (%s): the emptied result must apply", k, out.Skipped[k])
		}
	}
}

// TestSandboxReadoptDefaultsMatchTheDriver: the defaults the lowering-only
// merge resolves a local 0 to are the driver's own (LEFT2 audit S1).
func TestSandboxReadoptDefaultsMatchTheDriver(t *testing.T) {
	if got := time.Duration(SandboxReadoptDefaultBoundMinutes) * time.Minute; got != sandboxadopt.DefaultBound {
		t.Fatalf("bound default %v, the driver's is %v", got, sandboxadopt.DefaultBound)
	}
	if got := int64(SandboxReadoptDefaultCheckpointCapMiB) << 20; got != sandboxadopt.DefaultExportCapBytes {
		t.Fatalf("checkpoint cap default %d bytes, the driver's is %d", got, sandboxadopt.DefaultExportCapBytes)
	}
}
