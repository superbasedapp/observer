// Package buildfeat holds build-feature constants for removable components
// (plan 5.1): `const HasX = true` in the component's on file and `false` in
// its off file, so a call site inside a shared package can test whether the
// component is compiled in and the linker can drop the guarded code (the
// Tailscale buildfeatures lesson).
//
// Today it holds one hand-written pair, HasProcessobs
// (processobs_{on,off}.go, switched by the sbo_omit_processobs tag), whose
// only reader is a test that skips a case when process observation is
// compiled out. The plan's generation of these constants from
// internal/components was not built. A constant is a size optimisation and
// a test switch only, never the proof of removal: package absence in
// `go list -deps` is the only L1 proof.
package buildfeat
