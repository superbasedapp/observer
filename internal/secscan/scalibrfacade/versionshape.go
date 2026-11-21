//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/csproj"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/nugetcpm"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleversioncatalog"
)

// versionshape.go marks the declared versions that are not one version.
// A project file or a version catalog names what the build asks for, and
// that may be a range, a floating version or a property the build resolves
// later. SCALIBR's extractors pass such a string on as the version, and the
// matcher would then order a string that names no release. The facade marks
// the package Unpinned instead: depscan drops it before matching and reports
// its file "no exact version pinned", so the run is partial, never clean
// (the same rule as a requirements.txt range). Nothing here orders versions;
// it only reads their shape.

// notOneVersion is, per extractor (its plugin name, which plainPackage reads
// from the package), the rule that a version string is not one version.
var notOneVersion = map[string]func(string) bool{
	csproj.Name:               nugetNotOneVersion,
	nugetcpm.Name:             nugetNotOneVersion,
	gradleversioncatalog.Name: gradleNotOneVersion,
}

// nugetNotOneVersion reports a NuGet version that is not one version: an
// interval ("[1.0,2.0)", "(,1.0]"), a floating version ("1.*", "*") or an
// MSBuild property ("$(JsonVersion)"). An exact interval ("[1.2.3]") is one
// version, which the MSBuild rule unwraps first (exactNuGetVersion).
func nugetNotOneVersion(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "[") || strings.HasPrefix(v, "(") ||
		strings.Contains(v, "*") || strings.Contains(v, "$(")
}

// exactNuGetVersion unwraps an exact NuGet interval ("[1.2.3]" is exactly
// 1.2.3); any other string is returned as it is.
func exactNuGetVersion(v string) string {
	t := strings.TrimSpace(v)
	if len(t) > 2 && strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") && !strings.Contains(t, ",") {
		return strings.TrimSpace(t[1 : len(t)-1])
	}
	return v
}

// gradleNotOneVersion reports a version catalog version that is not one
// version: a Maven range ("[1.0,2.0)", "]1.0,2.0]", "(,1.0]"), a Gradle
// dynamic version ("1.+", "+") or a latest.* selector ("latest.release").
func gradleNotOneVersion(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "[") || strings.HasPrefix(v, "(") || strings.HasPrefix(v, "]") ||
		strings.HasSuffix(v, "+") || strings.HasPrefix(v, "latest.")
}
