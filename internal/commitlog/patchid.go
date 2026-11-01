package commitlog

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // git patch-id is defined over SHA-1; this is a content fingerprint, not a security boundary
	"encoding/hex"
	"strings"
)

// patchid.go computes a commit's patch fingerprint with `git patch-id
// --stable` semantics (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md
// 2.3 and 12.3): the same change applied under a new sha (a rebase merge, a
// cherry-pick) has the same fingerprint, so the delivery rules can tell that
// a commit landed even when its sha did not.
//
// It is a pure Go port of git's builtin/patch-id.c (get_one_patchid with
// stable=1) rather than a `git patch-id` subprocess: patch-id reads stdin and
// the read-only git seam (internal/gitview) has no stdin path, and the value
// is only ever compared with itself. TestPatchFingerprintMatchesGitPatchID
// cross-checks it against the real `git patch-id --stable` on a temp repo.
//
// Input is the output of
//
//	git diff-tree -p --no-renames --no-commit-id --root -r <sha>
//
// for one commit, or `git diff-tree -p --no-renames -r <base> <tip>` for the
// cumulative diff of a branch range (the squash fingerprint, rule L3): the
// same function fingerprints both.
//
// The algorithm, per file: every line from the "diff " header on is hashed
// with all whitespace removed, EXCEPT "index" lines, hunk headers ("@@ -..."
// whose line numbers would change with any unrelated edit above the hunk)
// and "\ No newline at end of file" markers. Each file's SHA-1 is added
// byte-wise (little-endian carry) into the result, so the fingerprint does
// not depend on the order files appear in.
//
// Binary files: git's own handling changed across versions (2.25 hashes the
// "Binary files ... differ" line, 2.40+ hashes the blob ids); this port
// keeps the 2.25 behaviour (the line is hashed like any header line).
// Because Observer only compares its own fingerprints with each other, that
// is consistent everywhere it matters. A diff whose every file is binary gets
// FingerprintBinaryOnly instead of a fingerprint: a pure binary change has no
// content worth matching on.

// MaxPatchBytes is the diff size cap (2 MiB). A larger diff is not
// fingerprinted (FingerprintTooLarge) and can only land by exact sha or by
// a provider PR record.
const MaxPatchBytes = 2 << 20

// FingerprintState is a fingerprint's state, the closed set
// internal/delivery stores in project_commits.patch_fp_state.
type FingerprintState string

// The FingerprintState values (the same strings as delivery.FP*).
const (
	FingerprintOK         FingerprintState = "ok"
	FingerprintTooLarge   FingerprintState = "too_large"
	FingerprintBinaryOnly FingerprintState = "binary_only"
	FingerprintEmpty      FingerprintState = "empty"
)

// PatchFingerprint returns the `git patch-id --stable` id (40 hex) of one
// diff, with its state. A fingerprint is returned only with FingerprintOK.
// Input over MaxPatchBytes is FingerprintTooLarge without being read.
func PatchFingerprint(diff []byte) (string, FingerprintState) {
	if len(diff) > MaxPatchBytes {
		return "", FingerprintTooLarge
	}
	var (
		result     [sha1.Size]byte
		h          = sha1.New() //nolint:gosec // G401: git patch-id is defined over SHA-1; a matching fingerprint, not a security boundary
		patchLen   int
		before     = -1
		after      = -1
		files      int
		binaryOnly = 0
		fileBinary bool
	)
	flush := func() {
		var sum [sha1.Size]byte
		copy(sum[:], h.Sum(nil))
		h.Reset()
		carry := 0
		for i := 0; i < sha1.Size; i++ {
			carry += int(result[i]) + int(sum[i])
			result[i] = byte(carry)
			carry >>= 8
		}
	}
	endFile := func() {
		if files > 0 && fileBinary {
			binaryOnly++
		}
		fileBinary = false
	}

	for _, raw := range splitLinesKeepNL(diff) {
		line := string(raw)
		if isNoNewlineMarker(line) {
			continue
		}
		if isCommitHeader(line) {
			if patchLen > 0 {
				break // a second commit's patch starts: one patch per call
			}
			continue
		}
		// Commit message text before the first diff header is ignored.
		if patchLen == 0 && !strings.HasPrefix(line, "diff ") {
			continue
		}
		if before == -1 {
			switch {
			case strings.HasPrefix(line, "index "):
				continue
			case strings.HasPrefix(line, "--- "):
				before, after = 1, 1
			case strings.HasPrefix(line, "Binary files ") || strings.HasPrefix(line, "GIT binary patch"):
				fileBinary = true
			case strings.HasPrefix(line, "diff "):
				// A new file's header. The first one opens the first file.
				if files > 0 {
					endFile()
				}
				files++
			case line == "" || !isAlpha(line[0]):
				goto done
			}
		}
		if before == 0 && after == 0 {
			if strings.HasPrefix(line, "@@ -") {
				before, after = scanHunkHeader(line)
				continue
			}
			if !strings.HasPrefix(line, "diff ") {
				goto done
			}
			flush()
			endFile()
			files++
			before, after = -1, -1
		}
		switch line[0] {
		case '-':
			before--
		case '+':
			after--
		case ' ':
			before--
			after--
		}
		n := writeNoSpace(h, line)
		patchLen += n
	}
done:
	if files > 0 {
		endFile()
	}
	if patchLen == 0 {
		return "", FingerprintEmpty
	}
	flush()
	if binaryOnly == files {
		return "", FingerprintBinaryOnly
	}
	return hex.EncodeToString(result[:]), FingerprintOK
}

// PatchFiles returns the repository-relative paths a diff touches, in order,
// read from its "diff --git a/<p> b/<p>" headers (the b/ side; the a/ side
// for a deletion is the same path with --no-renames). Quoted paths are
// returned with their C-style quotes removed but escapes kept, which is
// enough to compare two file sets from the same git.
func PatchFiles(diff []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range bytes.Split(diff, []byte{'\n'}) {
		line := string(raw)
		if !strings.HasPrefix(line, "diff --git ") {
			continue
		}
		rest := line[len("diff --git "):]
		i := strings.LastIndex(rest, " b/")
		if i < 0 {
			i = strings.LastIndex(rest, ` "b/`)
			if i < 0 {
				continue
			}
			rest = strings.TrimSuffix(rest[i+4:], `"`)
		} else {
			rest = rest[i+3:]
		}
		if rest != "" && !seen[rest] {
			seen[rest] = true
			out = append(out, rest)
		}
	}
	return out
}

// splitLinesKeepNL splits b into lines, each keeping its trailing newline.
func splitLinesKeepNL(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

// isNoNewlineMarker mirrors patch-id's skip of "\ No newline at end of file"
// (any "\ " line longer than 12 bytes).
func isNoNewlineMarker(line string) bool {
	return strings.HasPrefix(line, `\ `) && len(line) > 12
}

// isCommitHeader reports whether line is a commit header patch-id treats as
// the start of the next patch: a full hex object id, optionally after
// "commit ", "From " or "diff-tree ".
func isCommitHeader(line string) bool {
	p := line
	for _, pre := range []string{"diff-tree ", "commit ", "From "} {
		if strings.HasPrefix(line, pre) {
			p = line[len(pre):]
			break
		}
	}
	for _, n := range []int{40, 64} {
		if len(p) >= n && isHex(p[:n]) && (len(p) == n || !isHexByte(p[n])) {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// isSpace is C isspace in the C locale.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// writeNoSpace hashes line with every whitespace byte removed (patch-id's
// remove_space) and returns the number of bytes hashed.
func writeNoSpace(h interface{ Write([]byte) (int, error) }, line string) int {
	buf := make([]byte, 0, len(line))
	for i := 0; i < len(line); i++ {
		if !isSpace(line[i]) {
			buf = append(buf, line[i])
		}
	}
	_, _ = h.Write(buf)
	return len(buf)
}

// scanHunkHeader parses "@@ -a[,b] +c[,d] @@" into the before / after line
// counts (b and d; 1 when omitted), as patch-id's scan_hunk_header does.
func scanHunkHeader(line string) (before, after int) {
	q := line[4:]
	n := spanDigits(q)
	before = 1
	if n < len(q) && q[n] == ',' {
		q = q[n+1:]
		before = atoiPrefix(q)
		n = spanDigits(q)
	}
	if n == 0 || n+1 >= len(q) || q[n] != ' ' || q[n+1] != '+' {
		return 0, 0
	}
	r := q[n+2:]
	n = spanDigits(r)
	after = 1
	if n < len(r) && r[n] == ',' {
		r = r[n+1:]
		after = atoiPrefix(r)
		n = spanDigits(r)
	}
	if n == 0 {
		return 0, 0
	}
	return before, after
}

func spanDigits(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

func atoiPrefix(s string) int {
	v := 0
	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		v = v*10 + int(s[i]-'0')
	}
	return v
}
