// Package secassessfixture is the structure and behaviour check of the
// deliberately vulnerable fixture application under testdata/secassess, the
// yardstick of the agent-run security assessments module (docs/plans/
// security-assessments-depth-plan-2026-11-14.md sections 7 and 8).
//
// The fixture is a small Python web application with 14 seeded weaknesses,
// 6 near-miss decoys and 3 mitigation traps, an answer key under
// testdata/secassess/truth (never copied into an assessment run) and
// hand-written golden results under testdata/secassess/golden. This package
// holds only the pure side of reading that answer key: the types of the three
// truth files (Manifest, ThreatModel, Probes), the anchor lookup that turns a
// code substring into a line, and the indicator evaluation that decides whether
// a response confirms a weakness. Nothing here touches a file, a socket or a
// process; the tests read the files and, only when
// OBSERVER_SECASSESS_FIXTURE=1 is set, start the application on a loopback
// port.
//
// The package is test support. No production command or package imports it;
// the scorer of the module (internal/secassess) reads the same JSON formats
// with its own types and stays standard-library only.
package secassessfixture
