package sandboxopenshell

import "strings"

// drivers.go is the compute-driver capability table probe row P6 and row
// P8e read (lane FU7, tracker F-033). A driver is accepted on a tested
// version only when a live receipt measured a box through it there: the
// Docker driver on every tested version (the O0 and O1B receipts), the
// Podman driver only on a tested version whose row names a passing O1B-L2
// launch receipt (TestedVersion.PodmanReceipt: the tmpfs home mode
// measured inside a Podman box, the run's record read back). Every other
// driver is refused.

// driverCaps is one driver's row.
type driverCaps struct {
	// measured reports whether a receipt measured this driver on the
	// tested version row.
	measured func(row TestedVersion) bool
	// engineIdentity: the engine answers a stable ID (`docker info`), so
	// row P8e applies. Podman's Docker-compatible API has none.
	engineIdentity bool
	// pullCLI is the engine CLI that pulls an image into the store this
	// driver's boxes start from (a reason's remedy for a missing image).
	pullCLI string
}

// driverTable is the closed driver set.
var driverTable = map[string]driverCaps{
	"docker": {measured: func(TestedVersion) bool { return true }, engineIdentity: true, pullCLI: "docker"},
	"podman": {measured: func(row TestedVersion) bool { return receiptSet(row.PodmanReceipt) }, engineIdentity: false, pullCLI: "podman"},
}

// driverNames are driverTable's keys in a fixed order (a reason that names
// every driver lists them in this order).
var driverNames = []string{"docker", "podman"}

// imagePullRemedy is the command that pulls ref for driver's engine, or,
// for a driver outside the table (the probe did not read one), the command
// of every driver, each named.
func imagePullRemedy(driver, ref string) string {
	if c, ok := driverTable[driver]; ok {
		return "`" + c.pullCLI + " pull " + ref + "`"
	}
	out := make([]string, 0, len(driverNames))
	for _, d := range driverNames {
		out = append(out, "`"+driverTable[d].pullCLI+" pull "+ref+"` (the "+d+" driver)")
	}
	return strings.Join(out, " or ")
}

// driverConfigTable is the gateway.toml table that configures driver's
// images (audit FU9-A3: a reason under Podman names
// [openshell.drivers.podman], not the Docker table), or, for a driver
// outside the table (the probe did not read one), every driver's table,
// each named.
func driverConfigTable(driver string) string {
	if _, ok := driverTable[driver]; ok {
		return "[openshell.drivers." + driver + "]"
	}
	out := make([]string, 0, len(driverNames))
	for _, d := range driverNames {
		out = append(out, "[openshell.drivers."+d+"]")
	}
	return strings.Join(out, " or ") + " (the table of the driver in use)"
}

// pendingPrefix starts a receipt field that names no receipt yet.
const pendingPrefix = "PENDING"

// receiptSet reports whether a receipt field names a real receipt: not
// empty and not a pending placeholder (audit finding FU7-A1: the shipped
// table refuses the Podman driver until the passing receipt's path is
// written in).
func receiptSet(r string) bool {
	r = strings.TrimSpace(r)
	return r != "" && !strings.HasPrefix(r, pendingPrefix)
}

// DriverAccepted reports whether probe row P6 takes driver on the tested
// version row.
func DriverAccepted(driver string, row TestedVersion) bool {
	c, ok := driverTable[driver]
	return ok && c.measured(row)
}

// DriverHasEngineIdentity reports whether row P8e applies to driver.
func DriverHasEngineIdentity(driver string) bool {
	return driverTable[driver].engineIdentity
}

// PodmanMeasuredVersions lists the tested versions whose row names a
// Podman launch receipt (for a reason or a hint; "none" for none).
func PodmanMeasuredVersions() string {
	var out []string
	for _, r := range testedVersions {
		if DriverAccepted("podman", r) {
			out = append(out, r.Version.String())
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

// driverRefusal is probe row P6's reason for a driver it does not take.
func driverRefusal(driver string, v Version) string {
	if _, known := driverTable[driver]; known {
		return "the gateway's compute driver is " + quoteOr(driver, "unknown") + ", which no live receipt measured on OpenShell " + v.String() + " (Podman launch receipts: " + PodmanMeasuredVersions() + ")"
	}
	return "the gateway's compute driver is " + quoteOr(driver, "unknown") + "; only the Docker and Podman drivers are measured"
}
