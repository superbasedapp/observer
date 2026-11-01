package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/toolresolve/host"
)

// The login-env probe (surface-gap CLI-4, lane w4-homes-b). The hook, route
// and launcher writers follow this process's environment (relocate.go's
// rules through the registrars' Getenv). A tool home variable set in the
// developer's login shell but not here moves the tool's home without moving
// Observer's writes, so a hook or route lands in a home the tool no longer
// reads. The check compares the two for every variable the relocation table
// names. Run from the dashboard's per-tool checks it compares the login
// shell with the daemon itself.

// loginEnvCheckName is the doctor row's id.
const loginEnvCheckName = "config.home.login_env"

// loginEnvTimeout bounds one login-shell capture attempt.
const loginEnvTimeout = 3 * time.Second

// captureLoginEnv is the login-shell reader, memoized for the life of the
// process like daemonLoginPathDirs (a shell profile is not a moment in
// time, and a doctor run must not pay a capture per call).
var captureLoginEnv = func() func(string, []string, time.Duration) (map[string]string, error) {
	var (
		once sync.Once
		got  map[string]string
		err  error
	)
	return func(shell string, names []string, timeout time.Duration) (map[string]string, error) {
		once.Do(func() { got, err = host.CaptureLoginEnv(shell, names, timeout) })
		return got, err
	}
}()

// loginEnvDriftCheck is the doctor row for this process.
func loginEnvDriftCheck() diag.Check {
	return loginEnvDriftCheckWith(runtime.GOOS, os.Getenv("SHELL"), os.Getenv, captureLoginEnv)
}

// loginEnvDriftCheckWith is loginEnvDriftCheck with its inputs injected.
func loginEnvDriftCheckWith(goos, shell string, getenv func(string) string, capture func(string, []string, time.Duration) (map[string]string, error)) diag.Check {
	c := diag.Check{Name: loginEnvCheckName, Status: diag.StatusOK}
	if goos == "windows" {
		c.Message = "not checked on Windows (no POSIX login shell sets the environment there)"
		return c
	}
	names := agentconfig.RelocationVariables()
	login, err := capture(shell, names, loginEnvTimeout)
	if err != nil {
		c.Message = "the login shell's environment could not be read, so tool home variables were not compared (" + err.Error() + ")"
		return c
	}
	drift := agentconfig.RelocationEnvDrift(names, func(n string) string { return login[n] }, getenv)
	if len(drift) == 0 {
		c.Message = fmt.Sprintf("this process sees every tool home variable your login shell sets (%d compared)", len(names))
		return c
	}
	c.Status = diag.StatusWarn
	c.Message = fmt.Sprintf("%d tool home variable(s) are set in your login shell but differ here, so Observer's hooks and routes may land in a home the tool does not read", len(drift))
	for _, d := range drift {
		here := d.Process
		if here == "" {
			here = "(unset)"
		}
		c.Details = append(c.Details, fmt.Sprintf("%s: login shell %s, this process %s; set it where the daemon starts (or unset it in the profile) and run observer init again", d.Name, d.Login, here))
	}
	return c
}
