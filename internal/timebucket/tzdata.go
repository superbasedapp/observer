package timebucket

// The IANA zone database is compiled into every binary that buckets charts
// (~450 KB). LoadZone is the one place a viewer zone is resolved, and this
// package is linked by every binary that serves a time-series chart
// (cmd/observer, cmd/observer-org, and the two companions that link the org
// server), so importing it HERE covers all of them, including any future
// binary that buckets, without a per-main import to forget.
//
// Without it, a host with no system zone database fails every
// time.LoadLocation: a Windows node (release builds use -trimpath, so
// GOROOT/lib/time/zoneinfo.zip is not found) or a distroless/stripped
// container would bucket every chart in UTC with tz_fallback set. Go
// consults this embedded copy only after the system database fails, so a
// host that has one keeps using it.
import _ "time/tzdata"
