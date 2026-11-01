package integration

import "time"

// WindowsFirstHookFloor is the smallest host hook timeout a hook binding
// that registers on Windows may carry (roadmap F0-3 revision 2.1, the JSP-2
// laptop half): the first hook after every Windows binary update costs
// about 2 s (p99 up to 3.9 s) while Microsoft Defender scans the new
// executable on its first run, so a host that cut the hook off sooner
// would fail that hook (open on most hosts). A registered binding either
// leaves the host timeout unset (the host's own default, named in
// hookfloor_test.go) or sets one of at least this value, and every
// registration writer writes at least this value where it writes one
// (TestHookTimeoutFloor, TestRegistrationWritersKeepTheFloor). The sandbox
// lane that sets its own hook timeouts (SBX-P6) reads this constant.
const WindowsFirstHookFloor = 4 * time.Second
