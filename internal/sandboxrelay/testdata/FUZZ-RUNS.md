# Fuzz runs of the relay protocol

Three targets (sandbox plan section 13.12, A5; JSP-3): `FuzzReaderRaw` (raw
bytes through the full reader), `FuzzOpenerSealed` (sealed operations
against a reference model) and, since lane sbx-p2c (plans decision log
P-032), `FuzzForwardRekey` (sealed guest scripts through the host's
cut-through `Session.Forward` with re-keying every 48 bytes; it checks that
a returned message passes the whole check, that the next hop got exactly
it, and that the next hop never holds a whole message when Forward failed).
The seed corpus under `fuzz/` is the JSP-3 corpus (`_spikes/jsp-3/corpus/`);
`FuzzForwardRekey` is seeded with valid scripts plus every entry of the
other two targets' corpus.

| Date (UTC) | Where | Target | Time | Executions | Corpus (new) | Crashes, hangs, property failures |
|---|---|---|---|---|---|---|
| 2026-10-21 03:37 | cloud session, lane sbx-p2, `-parallel 1` each, both at once | FuzzReaderRaw | 10 min | 7,814,232 | 19 (10) | none |
| 2026-10-21 03:37 | same | FuzzOpenerSealed | 10 min | 6,834,575 | 127 (16) | none |
| 2026-10-21 06:50 | cloud session, lane sbx-p2b (after the reader read whatever has arrived per call and the frame buffers were pooled), `-parallel 1` each, both at once | FuzzReaderRaw | 10 min | 6,182,729 | 18 (9) | none |
| 2026-10-21 06:50 | same | FuzzOpenerSealed | 10 min | 5,351,289 | 132 (21) | none |
| 2026-10-21 (lane sbx-p2c) | cloud session, 4 vCPU Xeon with SHA instructions, `-parallel 4`, alone except for short package tests in parallel | FuzzForwardRekey | 11 min | 8,995,525 | 651 (534) | none |

Command: `go test -run '^$' -fuzz '^FuzzReaderRaw$' -fuzztime 10m -parallel 1
./internal/sandboxrelay/` (and the same for `FuzzOpenerSealed`; lane sbx-p2c
ran `-fuzz '^FuzzForwardRekey$' -fuzztime 11m -parallel 4`). The longer
run per release is owed (`_spikes/jsp-3/run-fuzz.sh 8h` shape).
