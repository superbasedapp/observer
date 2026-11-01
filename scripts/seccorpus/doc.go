// Command seccorpus runs the observer-code rule pack's precision corpus
// (security pillar plan PR7 and section 5.5, Phase G lane G3; spikes JSP-7
// and JSP-8; operator ruling P-047). It is a maintainer tool: no shipped
// binary imports it, and nothing it writes is read at run time except the
// figures it records into the pack's own pack.json.
//
//	seccorpus clone   -dest DIR [-self CHECKOUT]
//	seccorpus scan    -dest DIR -opengrep BIN [-jobs 4]
//	seccorpus packets -dest DIR -out DIR [-batch 60] [-cap 60] [-label-seed N] [-full RULE,RULE]
//	seccorpus labels  -packets DIR -reviewer a|b -in DIR
//	seccorpus measure [-second-pass-pending]
//	seccorpus sample  [-seed N] [-per 5] [-max 150] [-scope auto|cleared|all]
//	seccorpus record  -date YYYY-MM-DD
//	seccorpus table
//
// clone fetches each repository of corpus/repos.tsv at its pinned commit
// into DIR, a scratch directory that must lie outside this checkout (this
// repository itself comes from -self, the local checkout, at its pinned
// commit). Git runs with hooks, filters' LFS smudge and file transport off.
//
// scan runs the pack over each clone through the G1 driver
// (internal/secscan/opengrep, a full scan with the canary), with the
// pinned Opengrep at BIN, and writes the candidate findings
// (corpus/candidates.jsonl: repository URL, commit, path, line, rule id),
// the per-rule counts (corpus/counts.tsv) and the run record
// (corpus/run.json: every repository with its outcome; one that failed to
// clone or scan is listed there, never dropped).
//
// packets selects the findings to label (corpus/labelset.jsonl: every
// result of a rule with at most -cap, otherwise a seeded sample of -cap;
// JSP-8 step 3; every result of each rule named by -full, the rules
// proposed for blocking, ruling P-077; its header line records the cap,
// the seed and the full list) and writes the reviewers' packets into a
// scratch directory: the labelling rubric, each rule's text and, per
// finding, a bounded excerpt read from the clone now. Packets carry source
// text, so they are never committed. It also writes the skeleton of the
// content-free batch manifest (corpus/batches.tsv: one row per batch per
// side, its packet count and the sha256 of its packet id list), whose
// reviewer and run agent columns whoever runs the reviewers fills in.
//
// labels imports one reviewer's labels into corpus/labels-a.jsonl or
// labels-b.jsonl from a directory of per-batch files (batch-NNN.jsonl, one
// JSON object per line: packet id, verdict, reason code). It refuses a
// label file whose batch is not in the manifest for that side, a manifest
// row not filled in, a reviewer that corpus/labellers.tsv does not list, a
// run agent shared by two batches or sides, and a batch whose packet ids
// are not the ones the manifest states.
//
// measure computes each rule's figures (internal/seccorpus.Measure: a
// finding is a true positive only when both reviewers say so) and writes
// them into corpus/figures.json and into the pack's pack.json, with
// blocking left off. With -second-pass-pending (lane SEC-G5) a finding
// labelled by side a only, while the side-b batches await their relabel,
// counts on side a's verdict; the figures then record the pending count,
// are one pass and never let a rule block.
//
// sample draws the spot-check sample, seeded and stratified per rule (every
// reviewer disagreement, at least half the both-true findings, at least
// seccorpus.MinSpotcheckSample rows or every both-true one), into
// corpus/operator-sample.tsv with an empty operator column: over the rules
// whose Wilson lower bound clears the bar, or, when none does, over every
// measured rule (-scope auto, the default). The file's "# draw:" line
// records the parameters.
//
// record reads the answered sample, draws it again from its "# draw:" line
// and refuses it unless it is exactly that draw; -reviewer names the
// spot-checker (agent:<id> of an independent AI reviewer or operator,
// never a labeller of corpus/labellers.tsv nor a run agent of
// corpus/batches.tsv, ruling P-064). In one step it writes each sampled
// rule's operator_spotcheck record (with the reviewer and the digest of the
// figures checked) and turns blocking on for exactly the rules that clear
// the bar (secrulepack.Rule.MayBlock, which needs every result labelled,
// P-077); it raises the pack version and
// refuses to write a pack the validator refuses; it then regenerates the
// table.
//
// table regenerates the per-rule table of docs/code-rules-precision.md
// from pack.json and corpus/counts.tsv (a test fails when it drifts).
package main
