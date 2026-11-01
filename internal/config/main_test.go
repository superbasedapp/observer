package config

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// TestMain fails the package run when any write outside the test temp
// directory was refused (FU-118), even one a test only logged.
func TestMain(m *testing.M) { os.Exit(testwriteguard.Run(m)) }
