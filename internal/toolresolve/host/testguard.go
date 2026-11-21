package host

import (
	"errors"
	"os"
	"testing"
)

// AllowLoginShellInTestEnv, set to "1" on a `go test` command line, lets the
// production capture start the operator's real login shell inside a test
// binary again (a manual probe). Same discipline as crossmount's
// AllowLiveForeignHomesInTestEnv and notify's AllowRealNotifyInTestEnv.
const AllowLoginShellInTestEnv = "OBSERVER_ALLOW_LOGIN_SHELL_IN_TEST"

// ErrLoginShellInTest is what a login capture returns inside a `go test`
// binary that did not open AllowLoginShellInTestEnv. Every caller already
// treats a capture error as "no login merge" (the process PATH alone), so a
// test that reaches the capture through a production path (host.NewEnv's
// LoginPath, CaptureLoginPath, CaptureLoginEnv) resolves without it.
var ErrLoginShellInTest = errors.New("toolresolve/host: the login shell capture is off inside a go test binary")

// loginShellBlocked is true inside a `go test` binary unless the operator
// opened AllowLoginShellInTestEnv (tracker F-031). Before it, any test that
// reached the capture (TestSandboxCLIToolPath through dashResolveEnv, among
// others) started the developer's real `bash -lic`: it read their rc files,
// could take their terminal and stop the test binary's whole process group,
// and made the test depend on the machine. The guard lives at the one place
// every capture execs, so no test can forget it; this package's own tests
// that drive a fake shell open it per test (allowFakeLoginShell). Production
// cost: testing.Testing() is one read at package init.
var loginShellBlocked = testing.Testing() && os.Getenv(AllowLoginShellInTestEnv) != "1"
