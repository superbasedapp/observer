package sandboxmxc

// mxcProcessGolden is the digest of the mxc-process probe ladder's results
// and probe document on the recorded answers in TestMXCProcessProbeGolden,
// taken at the lane GATES-SBX base (399f5300b), re-taken when every
// document gained the ui block (Windows 11 Pro rerun 2026-10-25, D1) and
// when it gained processContainer.ui (WINFIX2 audit finding 3), and when the
// probes kept the Win32k mitigation (finding 4: only a tool that needs
// user32.dll drops it).
const mxcProcessGolden = "fd6b40e3ab693c38603c4b5ec30a964d906a151db84ddfd63e920fdb2afaf931"
