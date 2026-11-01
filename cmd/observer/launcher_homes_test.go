package main

import (
	"path/filepath"
	"testing"
)

// TestLauncherModelsFilesFollowTheToolHome (S-17, lane w4-homes-b): the pi
// and prime-agent launchers write their session provider into the
// models.json the launched tool reads, which its home variable moves. The
// old launchers hard-coded ~/.pi/agent and ~/.prime/agent.
func TestLauncherModelsFilesFollowTheToolHome(t *testing.T) {
	home := t.TempDir()
	alt := filepath.Join(t.TempDir(), "agent")
	for _, tc := range []struct {
		name, id string
		env      map[string]string
		want     string
		wantErr  bool
	}{
		{"pi default", "pi/user-models", nil, filepath.Join(home, ".pi", "agent", "models.json"), false},
		{"pi PI_CODING_AGENT_DIR", "pi/user-models", map[string]string{"PI_CODING_AGENT_DIR": alt}, filepath.Join(alt, "models.json"), false},
		{"pi relative", "pi/user-models", map[string]string{"PI_CODING_AGENT_DIR": "rel"}, "", true},
		{"prime default", primeAgentModelsArtifact, nil, filepath.Join(home, ".prime", "agent", "models.json"), false},
		{"prime env", primeAgentModelsArtifact, map[string]string{"PRIME_AGENT_CODING_AGENT_DIR": alt}, filepath.Join(alt, "models.json"), false},
		{"prime tilde", primeAgentModelsArtifact, map[string]string{"PRIME_AGENT_CODING_AGENT_DIR": "~/pa"}, filepath.Join(home, "pa", "models.json"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			got, err := launcherArtifactPathAt(tc.id, home, func(k string) string { return env[k] })
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("got %q, %v; want %q (error %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
