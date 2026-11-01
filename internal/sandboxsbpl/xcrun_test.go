package sandboxsbpl

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestNoXcrunCacheGrant pins register MAC-38 (lane SBX-UPD): Apple
// documents no route that moves xcrun's lookup cache (xcrun_db in the
// user's hidden temp directory) into the run's TMPDIR (xcrun(1) offers
// only --no-cache / xcrun_nocache, which skips the lookup and refreshes
// the shared cache rather than moving it), so no profile on any tier
// grants the shared xcrun_db or the user temp directory it lives in, and
// no xcrun variable is set; the run's writable temp is its own directory.
// The shim's warning stays, recorded.
func TestNoXcrunCacheGrant(t *testing.T) {
	for _, tier := range []sandbox.Egress{sandbox.EgressInternet, sandbox.EgressProxyOnly, sandbox.EgressNone} {
		p, err := Build(baseRequest(tier))
		if err != nil {
			t.Fatal(err)
		}
		all := p.Text
		for _, x := range p.Params {
			all += "\n" + x.Name + "=" + x.Value
		}
		if strings.Contains(all, "xcrun") {
			t.Fatalf("tier %s: the profile names xcrun:\n%s", tier, all)
		}
		// The run's writable temp is its own directory, never the user
		// temp directory xcrun_db lives in.
		tmp := p.ParamMap()["TMP"]
		if tmp == "" || !strings.HasSuffix(tmp, "/run1") {
			t.Fatalf("tier %s: TMP = %q, want the run's own directory", tier, tmp)
		}
	}
}
