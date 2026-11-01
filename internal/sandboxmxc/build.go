package sandboxmxc

import "fmt"

// build.go is ProcessContainer's Windows build floor (MXC's
// os-version-support table, research companion part J): one row per
// servicing branch, with the update build revision (UBR) the PSEC
// BaseContainer API first shipped in. The floor only refuses a build that
// is clearly too old; a build at or above it is still probed by MXC's own
// check, because the build number alone does not say whether this edition
// offers PSEC (sandbox plan v2 section 4.7).

// BuildFloor is one servicing branch's floor.
type BuildFloor struct {
	// Build is the OS build number (26100 is 24H2, 26200 is 25H2, 26300
	// is 26H2, 28000 is 26H1).
	Build int
	// MinUBR is the first update build revision with BaseContainer.
	MinUBR int
	// Name is the branch's marketing name, for the reason text.
	Name string
}

// BuildFloors is the floor table, ordered by build.
var BuildFloors = []BuildFloor{
	{Build: 26100, MinUBR: 9278, Name: "Windows 11 24H2"},
	{Build: 26200, MinUBR: 9278, Name: "Windows 11 25H2"},
	{Build: 26300, MinUBR: 9550, Name: "Windows 11 26H2"},
	{Build: 28000, MinUBR: 2804, Name: "Windows 11 26H1"},
}

// CheckBuild judges a build and UBR against the floor table. A build below
// the lowest row, or a known branch below its UBR, is psec_build_too_old.
// A build between rows that has no row of its own (an Insider branch) is
// too old when it is below the next row, and a build above the highest row
// passes the floor (the probe decides).
func CheckBuild(build, ubr int) Verdict {
	if build <= 0 {
		return Verdict{Code: VerdictPSECBuildTooOld, Reason: "the Windows build could not be read"}
	}
	lowest := BuildFloors[0]
	if build < lowest.Build {
		return Verdict{Code: VerdictPSECBuildTooOld, Reason: fmt.Sprintf("Windows build %d.%d is below MXC ProcessContainer's floor (%s, %d.%d or later)", build, ubr, lowest.Name, lowest.Build, lowest.MinUBR)}
	}
	for i, f := range BuildFloors {
		if build == f.Build {
			if ubr < f.MinUBR {
				return Verdict{Code: VerdictPSECBuildTooOld, Reason: fmt.Sprintf("Windows build %d.%d is below MXC ProcessContainer's floor for %s (%d.%d); install the latest cumulative update", build, ubr, f.Name, f.Build, f.MinUBR)}
			}
			return Verdict{Code: VerdictAvailable}
		}
		if i+1 < len(BuildFloors) && build > f.Build && build < BuildFloors[i+1].Build {
			return Verdict{Code: VerdictPSECBuildTooOld, Reason: fmt.Sprintf("Windows build %d.%d has no ProcessContainer floor of its own; use %s %d.%d or later", build, ubr, BuildFloors[i+1].Name, BuildFloors[i+1].Build, BuildFloors[i+1].MinUBR)}
		}
	}
	return Verdict{Code: VerdictAvailable}
}
