# cvss4 oracle producer

This directory makes the committed oracle fixtures of
`internal/secassess/cvss4/testdata` (what they hold and what they prove:
that directory's `README.md`). It was run once; nothing here runs in the build
or the test suite.

**It is a separate Go module on purpose.** `main.go` imports
`github.com/pandatix/go-cvss` (MIT) v0.6.4 to score vectors with an
implementation that shares no code or tables with the generated scorer. The
main module does not depend on it and must not: a `go.mod` change in the main
module triggers the full CI, and a scoring library the product never ships has
no place in its dependency set. Here it costs nothing, because `go build ./...`
and `go test ./...` of the main module stop at a nested `go.mod`.

## Remaking the fixtures

Needs Go, Node, `gh` (for the CVE records) and network access. Work in a
scratch directory; `UP` is `tools/cvss4gen/upstream`.

```sh
W=/tmp/cvss4-oracle && mkdir -p $W/sel $W/recs
cd tools/cvss4gen/oracle

# 1. the vectors to score: a stratified sample, grouped by FIRST's MacroVector
node select.js ../upstream $W/sel               # base-vectors.txt, full-vectors.txt

# 2. the independent scores (go-cvss v0.6.4)
go run . < $W/sel/base-vectors.txt > $W/base-gocvss.tsv
go run . < $W/sel/full-vectors.txt > $W/full-gocvss.tsv
go run . all-base                  > $W/allbase-gocvss.tsv   # all 104,976

# 3. FIRST's own calculator, for the divergence list and as a cross-check
node firstjs.js ../upstream all-base > $W/allbase-first.tsv

# 4. real CVE records that carry CVSS 4.0 base metrics
#    (list the records with GitHub code search, then fetch them at one commit)
SHA=$(gh api repos/CVEProject/cvelistV5/commits/main --jq .sha)
gh api -X GET search/code -f q='cvssV4_0 "AV:L" repo:CVEProject/cvelistV5' -f per_page=100 --jq '.items[].path' >> $W/paths.txt
#    (repeat with other metric tokens: "AV:A" "AV:P" "AC:H" "AT:P" "PR:H" "UI:A"
#     "VC:L" "SC:H" "SI:H" "SA:H" "VA:N"; space the calls: the search API allows
#     ten a minute)
sort -u $W/paths.txt | xargs -P 12 -I{} sh -c \
  'curl -fsS -o "$1/$(echo {} | tr / _)" "https://raw.githubusercontent.com/CVEProject/cvelistV5/'$SHA'/{}"' _ $W/recs
node extract-cve.js $W/recs > $W/cve-rows.tsv
cut -f4 $W/cve-rows.tsv | sort -u > $W/cve-vectors.txt
go run . < $W/cve-vectors.txt > $W/cve-gocvss.tsv
node firstjs.js ../upstream stdin < $W/cve-vectors.txt | cut -f1,2 > $W/cve-first.tsv

# 5. write the fixtures
node mkfixtures.js $W ../../../internal/secassess/cvss4/testdata $SHA $(date -u +%F)
```

The CVE records the committed fixture holds came from `cvelistV5` commit
`9684f4fae3f0fa8a35f8d9b5e3d326940cf303d3`, listed by 12 code-search queries
(904 distinct record paths), of which 807 records were read and 533
base-only CVSS 4.0 entries kept (274 entries with threat or environmental
parts skipped). The search is not repeatable bit for bit, which is why the
fixtures, not the search, are the record.

## Files

| File | Role |
| --- | --- |
| `select.js` | chooses the vectors (FIRST's calculator only groups them by MacroVector; it provides no expected score) |
| `main.go`, `go.mod`, `go.sum` | the go-cvss runner, its own module |
| `firstjs.js` | runs FIRST's calculator JavaScript over vectors (cross-check only) |
| `extract-cve.js` | pulls the base-only CVSS 4.0 entries out of CVE records |
| `mkfixtures.js` | writes the six fixture files |
