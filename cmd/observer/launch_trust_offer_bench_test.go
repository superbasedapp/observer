//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_benchmark

package main

import (
	"context"
	"strings"
)

// The benchmark rows of TestTrustOfferedByDefault. A task whose repository
// is a local directory: each attempt's fresh workspace honours the source's
// accepts (observe goes on; enforce refuses naming the source until it is
// accepted, then every attempt goes on). A remote task on a driver that is
// not the inner launcher: observe goes on; enforce refuses and says to point
// the task at a local file:// clone and accept there.
func init() {
	trustOfferRows = append(trustOfferRows, func(e trustOfferEnv) {
		t := e.t
		var got []DriveRequest
		d := budgetControlledBenchmarkDriver{HarnessDriver: recordingHarness{got: &got}, configPath: e.cfgPath}
		drive := func(repo string) error {
			_, err := d.Drive(context.Background(), DriveRequest{WorkspaceDir: e.newClone(), TaskRepo: repo})
			return err
		}
		source := e.newClone()
		remote := "https://example.invalid/repo.git"
		switch e.mode {
		case "observe":
			if err := drive(source); err != nil {
				t.Fatalf("benchmark, local task, observe: %v", err)
			}
			if err := drive(remote); err != nil {
				t.Fatalf("benchmark, remote task, observe: %v", err)
			}
		case "enforce":
			if err := drive(source); err == nil || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+source) {
				t.Fatalf("benchmark, local task, enforce: %v, want a refusal naming the source", err)
			}
			e.accept(source)
			for i := 0; i < 2; i++ {
				if err := drive("file://" + source); err != nil {
					t.Fatalf("benchmark attempt %d after the source's accept: %v", i+1, err)
				}
			}
			if err := drive(remote); err == nil || !strings.Contains(err.Error(), "file:// URL") {
				t.Fatalf("benchmark, remote task, enforce: %v, want the local clone advice", err)
			}
		}
	})
}
