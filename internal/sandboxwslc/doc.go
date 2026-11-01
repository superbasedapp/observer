// Package sandboxwslc is the pure planner of the `wslc` sandbox row (WSL
// containers on Windows 11 through the wslc CLI; sandbox plan v2 sections
// 4.8 and 7.1, plan 17.1 row 35, lane GATES-SBX decision 6): the probe
// ladder over the facts a helper gathered, the run's argv and its exec
// argv for the relay over the exec's stdio (built only from flags the
// installed version's own help names), and the teardown that lists the
// run's containers before and after. Tier `none` only (--network none).
//
// No pinned wslc version's help and JSON are recorded yet (register WIN-5),
// so the probe refuses every version: the row is probe-only in this
// release. The package is pure (imports_test.go pins it).
package sandboxwslc
