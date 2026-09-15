package diag

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

func TestCheckPromptGuardWiring(t *testing.T) {
	base := func() config.Config {
		var cfg config.Config
		cfg.Guard.Enabled = true
		cfg.Guard.Mode = "enforce"
		cfg.Guard.Prompt.Enabled = true
		cfg.Guard.Prompt.HookLane = true
		cfg.Guard.Prompt.Mode = "ask-once"
		return cfg
	}

	t.Run("guard disabled", func(t *testing.T) {
		cfg := base()
		cfg.Guard.Enabled = false
		c := checkPromptGuardWiring(cfg)
		if c.Status != StatusOK {
			t.Errorf("Status = %v, want OK", c.Status)
		}
	})

	t.Run("guard mode off", func(t *testing.T) {
		cfg := base()
		cfg.Guard.Mode = "off"
		c := checkPromptGuardWiring(cfg)
		if c.Status != StatusOK {
			t.Errorf("Status = %v, want OK", c.Status)
		}
	})

	t.Run("prompt disabled warns", func(t *testing.T) {
		cfg := base()
		cfg.Guard.Prompt.Enabled = false
		c := checkPromptGuardWiring(cfg)
		if c.Status != StatusWarn {
			t.Errorf("Status = %v, want Warn", c.Status)
		}
	})

	t.Run("hook lane disabled warns", func(t *testing.T) {
		cfg := base()
		cfg.Guard.Prompt.HookLane = false
		c := checkPromptGuardWiring(cfg)
		if c.Status != StatusWarn {
			t.Errorf("Status = %v, want Warn", c.Status)
		}
	})

	t.Run("fully active is OK", func(t *testing.T) {
		c := checkPromptGuardWiring(base())
		if c.Status != StatusOK {
			t.Errorf("Status = %v, want OK", c.Status)
		}
	})
}
