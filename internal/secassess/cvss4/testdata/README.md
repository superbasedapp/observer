# cvss4 oracle fixtures

The scorer's tables are generated from FIRST's own calculator, so checking it
against that calculator would check the tables against themselves. These files
are the independent check: scores that came from a different implementation or
from real published records. All are committed, so the tests run offline.

| File | What it is | Rows |
| --- | --- | --- |
| `oracle_gocvss_base.tsv` | scores of `pandatix/go-cvss` v0.6.4 (MIT) for a stratified sample of the base vectors: up to 20 per reachable MacroVector (36), 2 per distinct score, 8 with no impact | 819 |
| `oracle_gocvss_full.tsv` | the same implementation's scores for full vectors (threat, environmental and supplemental metrics), 2 per MacroVector, all 270 covered; they reach the table rows a base vector never does (EQ4 = 0, EQ5 = 1 and 2, modified metrics) | 540 |
| `oracle_gocvss_space.txt` | sha256 and count of go-cvss's output over **all 104,976** base vectors, in the canonical nested order | 1 |
| `oracle_base_divergence.tsv` | every base vector, of all 104,976, on which go-cvss and FIRST's calculator differ | 72 |
| `oracle_cve.tsv` | CVSS 4.0 base vectors and scores published in real CVE records (`CVEProject/cvelistV5`, commit `9684f4fae3f0fa8a35f8d9b5e3d326940cf303d3`, 2026-11-15) | 271 distinct vectors from 533 entries in 807 records |
| `oracle_cve_disputed.tsv` | the published rows the scorer does not reproduce, with FIRST's and go-cvss's scores beside the record's | 4 |

How each was made, and the scripts that remake it, are in
`tools/cvss4gen/oracle/README.md`. The licences and notices are in
`THIRD_PARTY_NOTICES.md` at the repository root.

## What the tests prove

- The scorer reproduces go-cvss on the whole base space except 72 vectors, by
  digest (`TestOracleWholeBaseSpaceAgreesWithGoCVSSExceptTheTie`), and on 818 of
  the 819 sampled base vectors and 539 of the 540 full vectors, with each
  difference classified below.
- The scorer reproduces 267 of the 271 published CVE vectors exactly and the
  qualitative severity of the records is the rating the specification gives
  their published score in every one of the 271.
- Run against FIRST's own JavaScript (the same code the tables came from, used
  only as a cross-check of the Go port, `tools/cvss4gen/oracle/firstjs.js`) the
  Go scorer agrees on all 104,976 base vectors and on all 540 full vectors.

## The disagreements, all of them

**Rounding ties.** Every disagreement between independent implementations is an
exact tie: the unrounded score is `x.x5`, the two implementations hold it on
opposite sides of the half in float64, and the published scores differ by 0.1.
Exact decimal arithmetic (a test-only `math/big` reference,
`exact_test.go`) gives a third answer on some of the same vectors.

| Unrounded | FIRST's calculator (this scorer) | go-cvss | Exact decimal, half up | Base vectors | Band |
| --- | --- | --- | --- | --- | --- |
| 4.95 | 4.9 | 5.0 | 5.0 | 72 | medium either way |
| 5.65 | 5.6 | 5.6 | 5.7 | 432 (and 1 of the full vectors) | medium |
| 8.55 | 8.5 | 8.5 | 8.6 | 18 | high |
| 0.65 | 0.7 | 0.6 | 0.7 | none in the base space; 1 of the full vectors | low |

That is 522 of the 104,976 base vectors, about 0.5 percent, always by one tenth,
**never across a rating boundary** (`TestScoreMatchesExactArithmeticExceptFloatTies`
fails if one ever does). The scorer follows FIRST's calculator, because that is
what a developer sees when pasting the vector into FIRST's page and because the
tables are generated from it (decision D30): `cvss_score.js` ends in
`Math.round(value * 10) / 10` on float64, and the Go port repeats every
operation and its order (every product wrapped in `float64()` so a fused
multiply-add on arm64 cannot change a result). If the operator would rather
have exact decimal rounding, it is one function (`jsRound` plus an epsilon) and
the 522 rows above are the whole blast radius; this is a decision, not a bug.

One real record sits on a tie: **CVE-2026-46749** (Siemens,
`AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:H/SI:H/SA:H`) publishes 5.0, which
is the go-cvss and exact-decimal answer, not FIRST's 4.9.

**Three published scores that are wrong.** AMD's CVE-2025-0041 and CVE-2025-48506
publish 7.3 for a vector both calculators score 4.6; AMD's CVE-2025-61970
publishes 7.3 for a vector both score 1.0; Docker's CVE-2026-15793 publishes 6.5
for a vector both score 7.3. Each record's per-metric fields match its vector,
so the published score is the publisher's error. They are listed, with both
calculators' answers, in `oracle_cve_disputed.tsv` and pinned by name in the
test.

## Format

Tab-separated; lines starting with `#` are comments (the file's own header
repeats the column names and the source). The tests read them with `readTSV`
in `fixture_test.go`.
