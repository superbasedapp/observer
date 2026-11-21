package config

import (
	"testing"
	"time"
)

func TestSecurityReachGoDefaultsAndRanges(t *testing.T) {
	t.Parallel()
	var c SecurityReachGoConfig
	if c.MemoryBytes() != 12288<<20 || c.Timeout() != 1200*time.Second || c.MaxModules() != 16 {
		t.Fatalf("defaults: %d %s %d", c.MemoryBytes(), c.Timeout(), c.MaxModules())
	}
	if err := validateSecurityReachGo(c); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []SecurityReachGoConfig{
		{SourceMemoryMiB: 256},
		{SourceMemoryMiB: 70000},
		{SourceTimeoutSeconds: 10},
		{SourceTimeoutSeconds: 9000},
		{SourceMaxModules: -1},
		{SourceMaxModules: 65},
	} {
		if validateSecurityReachGo(bad) == nil {
			t.Errorf("%+v validated", bad)
		}
	}
	ok := SecurityReachGoConfig{SourceMemoryMiB: 2048, SourceTimeoutSeconds: 60, SourceMaxModules: 1}
	if err := validateSecurityReachGo(ok); err != nil || ok.MemoryBytes() != 2048<<20 || ok.Timeout() != time.Minute || ok.MaxModules() != 1 {
		t.Errorf("explicit values: %v", err)
	}
}
