// Command sbo-components is the build-side tool of the modular-packaging
// component catalog (docs/plans/modular-packaging-plan-2026-10-07.md,
// lane MP-CAT). It reads only internal/components.
//
//	sbo-components gen-docs [-o docs/components.md]   write the generated reference
//	sbo-components check [-o docs/components.md]      fail if the reference is stale or the catalog invalid
//	sbo-components tags --distro <name>               print every build tag a distro build passes (omit tags + stamp), comma separated
//	sbo-components tags --image <full|core>          print an observer-org image's build tags, comma separated
//	sbo-components ids --distro <name>                print the distro's compiled component ids, one per line
//	sbo-components distros                            print the stamped prebuilt distros (every one but full), one per line
//	sbo-components validate --distro <name>           check a distro's compiled set as a selection
//	sbo-components proof --distro <name> --binary <p>  the per-artifact proof gate (proof.go); --image core|full for observer-org
//	sbo-components sbom --distro <name> --binary <p>   the per-artifact CycloneDX SBOM; --image core|full for observer-org
//
// Custom builds (phase P7, lane MP-CUST, custom.go): every distro verb above
// also takes --manifest <m.toml> in place of --distro, plus
//
//	sbo-components manifest --manifest <m.toml> [--json] [-o c.json]  resolve and check a component manifest
//	sbo-components ldflags --manifest <m.toml> [--version v]          the -ldflags a custom build passes (the stamp)
//	sbo-components build --manifest <m.toml> [--goos --goarch ...]    build one custom binary with its evidence
//
// A later phase adds `gen-stubs` (P2).
package main
