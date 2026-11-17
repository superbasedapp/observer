# Third-party notices

This file lists third-party material that is copied into this repository (as
source, generated source or test data) and whose licence asks for a notice to
travel with it. Go module dependencies are listed by `go.mod` and their own
licences; the icon sources are in `shared/lib/THIRD_PARTY_ICONS.md`; the
vendored actionlint copy carries its licence in
`internal/thirdparty/actionlint/LICENSE.txt`.

## FIRST CVSS v4.0 calculator (BSD-2-Clause)

CVSS 4.0 base scoring in the agent-run security assessments module
(`internal/secassess/cvss4`) uses the score data of the calculator that FIRST
publishes for the CVSS v4.0 specification.

- Source: <https://github.com/FIRSTdotorg/cvss-v4-calculator>
- Commit: `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a` (2024-08-19), branch `main`
- Files used: `cvss_lookup.js`, `max_composed.js`, `max_severity.js`,
  `cvss_config.js`, `cvss_score.js`, and `LICENSE`. They are vendored,
  byte for byte, in `tools/cvss4gen/upstream/`, with the sha256 of each in
  `tools/cvss4gen/upstream/UPSTREAM`.
- Derived material: `internal/secassess/cvss4/tables_gen.go` is generated from
  those files by `tools/cvss4gen` (the MacroVector scores, the maximal vectors,
  the maximal severity distances and the severity levels); the scoring code in
  `internal/secassess/cvss4/score.go` follows the algorithm in `cvss_score.js`.
  The generated file carries this notice in its header.

The licence of those files is reproduced here as it requires.

```
Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

CVSS is owned and managed by FIRST.Org, Inc. (<https://www.first.org/cvss/>).
Observer implements the published scoring method; it does not reproduce the
specification document, and a CVSS line in Observer is the base score of a
vector as the specification's calculator computes it.

## pandatix/go-cvss (MIT), test oracle only

The expected scores in `internal/secassess/cvss4/testdata/oracle_gocvss_*.tsv`
and `oracle_base_divergence.tsv` were produced by running
<https://github.com/pandatix/go-cvss> v0.6.4 (commit
`8df5dbd1cdb98348548087af3157a7f96d7521ba`) once, from the separate nested
module `tools/cvss4gen/oracle`. None of its code is copied into this
repository's main module and the main module does not depend on it.

```
MIT License

Copyright (c) 2022 Lucas TESSON - PandatiX <lucastesson@protonmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## CVE Program records, test data only

`internal/secassess/cvss4/testdata/oracle_cve.tsv` and `oracle_cve_disputed.tsv`
hold the CVSS 4.0 base vectors and scores that real CVE records publish (CVE ids
and publishing organisations are named in the files), taken from
<https://github.com/CVEProject/cvelistV5> at commit
`9684f4fae3f0fa8a35f8d9b5e3d326940cf303d3`. CVE(R) is a registered trademark of
The MITRE Corporation. The records are used under the CVE Terms of Use,
<https://www.cve.org/Legal/TermsOfUse>; the data is facts (an identifier, a
vector and a score), not the records' descriptions.
