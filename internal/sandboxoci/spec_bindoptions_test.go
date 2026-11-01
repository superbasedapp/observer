package sandboxoci

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildCreateBindOptionsPerEngine (Linux live re-check on the Docker
// sandbox 2026-10-23, N2): rootless Podman's Docker-compatible create turns
// any BindOptions into a non-recursive bind, which runc refuses under
// keep-id over Podman's own locked shm mount, so the Podman body sends no
// BindOptions on any bind (Podman then mounts rbind, rprivate by default).
// Docker's body is unchanged: every bind, pin and hidden file states
// rprivate.
func TestBuildCreateBindOptionsPerEngine(t *testing.T) {
	podmanUser := UserPlan{Row: "rootless podman, keep-id", User: "1000:1000", UsernsMode: "keep-id", ExpectUIDMap: "1000:0:1"}
	for _, c := range []struct {
		name   string
		engine Engine
		user   UserPlan
		want   string // "" = no BindOptions
	}{
		{"docker", EngineDocker, rootfulUser, "rprivate"},
		{"podman", EnginePodman, podmanUser, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := pinsPlan()
			p.Engine, p.User = c.engine, c.user
			_, body, err := BuildCreate(p)
			if err != nil {
				t.Fatal(err)
			}
			binds := 0
			for _, m := range body.HostConfig.Mounts {
				if m.Type != "bind" {
					continue
				}
				binds++
				switch {
				case c.want == "" && m.BindOptions != nil:
					t.Errorf("bind %s carries BindOptions %+v", m.Target, *m.BindOptions)
				case c.want != "" && (m.BindOptions == nil || m.BindOptions.Propagation != c.want):
					t.Errorf("bind %s BindOptions %+v, want Propagation %s", m.Target, m.BindOptions, c.want)
				}
			}
			if binds != len(p.Binds)+len(p.Pins)+len(p.HideFiles) {
				t.Fatalf("%d binds rendered", binds)
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if has := strings.Contains(string(raw), `"BindOptions"`); has != (c.want != "") {
				t.Fatalf("BindOptions present=%v in the body: %s", has, raw)
			}
		})
	}
}
