package codequality

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Format is a coverage report format. The vocabulary is closed: a file in
// any other format is not read.
type Format string

// The closed Format vocabulary.
const (
	// FormatLCOV is the lcov tracefile (lcov.info): SF / DA / LF / LH
	// records. Written by Istanbul/nyc/c8/vitest/jest, lcov, cargo-llvm-cov,
	// coverage.py (`coverage lcov`) and many others.
	FormatLCOV Format = "lcov"
	// FormatCobertura is Cobertura XML (root <coverage>): coverage.py
	// (`coverage xml`), Istanbul's cobertura reporter, coverlet, gcovr.
	FormatCobertura Format = "cobertura"
	// FormatJaCoCo is JaCoCo's XML report (root <report>), Maven and
	// Gradle's default Java/Kotlin coverage output.
	FormatJaCoCo Format = "jacoco"
	// FormatGoCover is Go's coverprofile (`go test -coverprofile`),
	// first line "mode: set|count|atomic".
	FormatGoCover Format = "gocover"
)

// FileCoverage is one source file's line coverage within one report. Path
// is the report's own name for the file (an absolute path, a path relative
// to the report's source root, or a Go import path); it is display data.
type FileCoverage struct {
	Path    string
	Lines   int // instrumented lines
	Covered int // instrumented lines executed at least once
}

// Report is one parsed coverage report reduced to lines.
type Report struct {
	Format Format
	// Files is sorted by Path. Empty when TotalsOnly.
	Files []FileCoverage
	// Lines / Covered are the report's totals: the sum over Files, or the
	// report's own root totals when it carries no per-line records.
	Lines   int
	Covered int
	// TotalsOnly is true when the report had no per-line records and the
	// totals come from its summary attributes (a Cobertura root's
	// lines-valid/lines-covered, a JaCoCo report-level LINE counter).
	TotalsOnly bool
	// Skipped counts records the parser could not read (malformed lines);
	// they contribute nothing.
	Skipped int
}

// Errors a parser returns. A caller maps each to a Problem kind.
var (
	// ErrUnrecognized: the bytes are not one of the four formats.
	ErrUnrecognized = errors.New("codequality: not a recognized coverage report")
	// ErrNoLines: the report parsed but holds no instrumented line.
	ErrNoLines = errors.New("codequality: the report holds no instrumented lines")
)

// maxSpanLines bounds how many lines one Go coverprofile block may mark: a
// corrupt record must not allocate unbounded memory.
const maxSpanLines = 10000

// formatRow is one row of the sniff table: how to recognize a format from
// its first bytes and how to parse it.
type formatRow struct {
	Format Format
	Sniff  func(head []byte) bool
	Parse  func(data []byte) (Report, error)
}

// formatTable is walked top-down by Sniff; the first match decides. The two
// text formats are checked before the two XML ones because their first line
// is decisive; the XML rows decide on the root element name.
var formatTable = []formatRow{
	{Format: FormatGoCover, Sniff: sniffGoCover, Parse: parseGoCover},
	{Format: FormatLCOV, Sniff: sniffLCOV, Parse: parseLCOV},
	{Format: FormatCobertura, Sniff: func(h []byte) bool { return xmlRoot(h) == "coverage" }, Parse: parseCobertura},
	{Format: FormatJaCoCo, Sniff: func(h []byte) bool { return xmlRoot(h) == "report" }, Parse: parseJaCoCo},
}

// sniffBytes is how much of a file Sniff looks at.
const sniffBytes = 8 << 10

// Sniff names the format of data from its first bytes, or ok=false.
func Sniff(data []byte) (Format, bool) {
	head := trimLead(data)
	if len(head) > sniffBytes {
		head = head[:sniffBytes]
	}
	for _, row := range formatTable {
		if row.Sniff(head) {
			return row.Format, true
		}
	}
	return "", false
}

// ParseCoverage sniffs data and parses it with its format's parser.
func ParseCoverage(data []byte) (Report, error) {
	f, ok := Sniff(data)
	if !ok {
		return Report{}, ErrUnrecognized
	}
	for _, row := range formatTable {
		if row.Format == f {
			r, err := row.Parse(trimLead(data))
			if err != nil {
				return Report{}, err
			}
			if r.Lines == 0 {
				return Report{}, ErrNoLines
			}
			return r, nil
		}
	}
	return Report{}, ErrUnrecognized
}

// trimLead drops a UTF-8 byte-order mark and leading whitespace.
func trimLead(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	return bytes.TrimLeft(b, " \t\r\n")
}

// firstLine returns the first line of b without its line ending.
func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return strings.TrimRight(string(b), "\r")
}

func sniffGoCover(h []byte) bool {
	switch firstLine(h) {
	case "mode: set", "mode: count", "mode: atomic":
		return true
	}
	return false
}

func sniffLCOV(h []byte) bool {
	l := firstLine(h)
	return strings.HasPrefix(l, "TN:") || strings.HasPrefix(l, "SF:")
}

// xmlRoot returns the local name of the first element in h, "" when h is
// not XML or the head ends before one. DOCTYPE and processing instructions
// are skipped; the decoder never fetches or expands an external entity.
func xmlRoot(h []byte) string {
	if len(h) == 0 || h[0] != '<' {
		return ""
	}
	d := xml.NewDecoder(bytes.NewReader(h))
	d.CharsetReader = passCharset
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Local
		}
	}
}

// passCharset accepts the ASCII-compatible declarations report writers use
// (JaCoCo and some Cobertura writers declare ISO-8859-1 or US-ASCII). The
// fields read here (paths, numbers) are ASCII in practice; a non-ASCII byte
// in a path is shown as written.
func passCharset(label string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin1", "windows-1252":
		return in, nil
	}
	return nil, fmt.Errorf("codequality: unsupported XML encoding %q", label)
}

// lineSet accumulates per-file line coverage: line -> executed at least once.
type lineSet map[string]map[int]bool

func (s lineSet) mark(file string, line int, covered bool) {
	m := s[file]
	if m == nil {
		m = map[int]bool{}
		s[file] = m
	}
	m[line] = m[line] || covered
}

// files folds the set into sorted FileCoverage rows and the totals.
func (s lineSet) files() ([]FileCoverage, int, int) {
	out := make([]FileCoverage, 0, len(s))
	var lines, covered int
	for path, m := range s {
		fc := FileCoverage{Path: path, Lines: len(m)}
		for _, c := range m {
			if c {
				fc.Covered++
			}
		}
		lines += fc.Lines
		covered += fc.Covered
		out = append(out, fc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, lines, covered
}

// parseGoCover reads a Go coverprofile. Each block is
// "file:startLine.startCol,endLine.endCol numStmt count"; a block with
// statements marks every line it spans, executed when count > 0. Blocks
// repeated across merged profiles (several test binaries, -coverpkg) fold
// by line, so a line is covered when any block covering it ran.
func parseGoCover(data []byte) (Report, error) {
	set := lineSet{}
	var skipped int
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue // the mode line
		}
		if line == "" {
			continue
		}
		file, start, end, stmts, count, ok := parseGoBlock(line)
		if !ok {
			skipped++
			continue
		}
		if stmts == 0 {
			continue
		}
		for l := start; l <= end; l++ {
			set.mark(file, l, count > 0)
		}
	}
	if err := sc.Err(); err != nil {
		return Report{}, fmt.Errorf("codequality.parseGoCover: %w", err)
	}
	files, lines, covered := set.files()
	return Report{Format: FormatGoCover, Files: files, Lines: lines, Covered: covered, Skipped: skipped}, nil
}

// parseGoBlock splits one coverprofile block line.
func parseGoBlock(line string) (file string, start, end, stmts int, count int64, ok bool) {
	colon := strings.LastIndexByte(line, ':')
	if colon <= 0 {
		return "", 0, 0, 0, 0, false
	}
	file = line[:colon]
	fields := strings.Fields(line[colon+1:])
	if len(fields) != 3 {
		return "", 0, 0, 0, 0, false
	}
	span := strings.SplitN(fields[0], ",", 2)
	if len(span) != 2 {
		return "", 0, 0, 0, 0, false
	}
	start, okS := lineOf(span[0])
	end, okE := lineOf(span[1])
	n, errN := strconv.Atoi(fields[1])
	c, errC := strconv.ParseInt(fields[2], 10, 64)
	if !okS || !okE || errN != nil || errC != nil || n < 0 || start <= 0 || end < start || end-start > maxSpanLines {
		return "", 0, 0, 0, 0, false
	}
	return file, start, end, n, c, true
}

// lineOf reads the line half of "line.col".
func lineOf(s string) (int, bool) {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// lcovFile is one lcov source file's accumulated records.
type lcovFile struct {
	lines  map[int]bool
	lf, lh int
}

// parseLCOV reads an lcov tracefile. DA records decide when present; a
// record with only LF/LH summary lines contributes those totals. Records
// for the same SF (a merged tracefile) fold by line.
func parseLCOV(data []byte) (Report, error) {
	byFile := map[string]*lcovFile{}
	var cur *lcovFile
	var skipped int
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "SF:"):
			path := strings.TrimSpace(line[3:])
			cur = byFile[path]
			if cur == nil {
				cur = &lcovFile{lines: map[int]bool{}}
				byFile[path] = cur
			}
		case line == "end_of_record":
			cur = nil
		case cur == nil:
			// TN:, a comment, or a record outside SF ... end_of_record.
		case strings.HasPrefix(line, "DA:"):
			parts := strings.Split(line[3:], ",")
			if len(parts) < 2 {
				skipped++
				continue
			}
			n, err1 := strconv.Atoi(parts[0])
			hits, err2 := strconv.ParseFloat(parts[1], 64) // some writers emit "1.0"
			if err1 != nil || err2 != nil || n <= 0 {
				skipped++
				continue
			}
			cur.lines[n] = cur.lines[n] || hits > 0
		case strings.HasPrefix(line, "LF:"):
			if n, err := strconv.Atoi(line[3:]); err == nil && n > cur.lf {
				cur.lf = n
			}
		case strings.HasPrefix(line, "LH:"):
			if n, err := strconv.Atoi(line[3:]); err == nil && n > cur.lh {
				cur.lh = n
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Report{}, fmt.Errorf("codequality.parseLCOV: %w", err)
	}
	r := Report{Format: FormatLCOV, Skipped: skipped}
	for path, f := range byFile {
		fc := FileCoverage{Path: path}
		if len(f.lines) > 0 {
			fc.Lines = len(f.lines)
			for _, c := range f.lines {
				if c {
					fc.Covered++
				}
			}
		} else {
			fc.Lines, fc.Covered = f.lf, min(f.lh, f.lf)
		}
		if fc.Lines == 0 {
			continue
		}
		r.Lines += fc.Lines
		r.Covered += fc.Covered
		r.Files = append(r.Files, fc)
	}
	sort.Slice(r.Files, func(i, j int) bool { return r.Files[i].Path < r.Files[j].Path })
	return r, nil
}

// attr returns the value of the named attribute, "" when absent.
func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// atoi64 parses a non-negative integer attribute; ok=false otherwise.
func atoi64(s string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n, err == nil && n >= 0
}

// parseCobertura reads Cobertura XML. Only a <line> directly inside a
// class's own <lines> counts: Cobertura repeats every method's lines under
// <methods>/<method>/<lines>, which would double-count. Several classes of
// one file fold by line. A report with no line records falls back to the
// root's lines-valid / lines-covered.
func parseCobertura(data []byte) (Report, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = passCharset
	set := lineSet{}
	var stack []string
	var file string
	var rootValid, rootCovered int64
	var rootTotals, sawRoot bool
	var skipped int
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Report{}, fmt.Errorf("codequality.parseCobertura: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			switch {
			case len(stack) == 0:
				if name != "coverage" {
					return Report{}, ErrUnrecognized
				}
				sawRoot = true
				v, okV := atoi64(attr(t, "lines-valid"))
				c, okC := atoi64(attr(t, "lines-covered"))
				if okV && okC {
					rootValid, rootCovered, rootTotals = v, c, true
				}
			case name == "class":
				file = attr(t, "filename")
			case name == "line" && len(stack) >= 2 && stack[len(stack)-1] == "lines" && stack[len(stack)-2] == "class" && file != "":
				n, okN := atoi64(attr(t, "number"))
				h, okH := atoi64(attr(t, "hits"))
				if !okN || !okH || n == 0 {
					skipped++
				} else {
					set.mark(file, int(n), h > 0)
				}
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) > 0 {
				if stack[len(stack)-1] == "class" {
					file = ""
				}
				stack = stack[:len(stack)-1]
			}
		}
	}
	if !sawRoot {
		return Report{}, ErrUnrecognized
	}
	files, lines, covered := set.files()
	r := Report{Format: FormatCobertura, Files: files, Lines: lines, Covered: covered, Skipped: skipped}
	if lines == 0 && rootTotals {
		r.Files = nil
		r.Lines, r.Covered, r.TotalsOnly = int(rootValid), int(min(rootCovered, rootValid)), true
	}
	return r, nil
}

// parseJaCoCo reads JaCoCo XML: <package name>/<sourcefile name>/<line nr
// mi ci>. A line is instrumented when mi+ci > 0 and covered when ci > 0. A
// report with no line records falls back to its report-level LINE counter.
//
//nolint:gocyclo // one case per JaCoCo XML element in a single streaming pass; complexity tracks the format's element count.
func parseJaCoCo(data []byte) (Report, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = passCharset
	set := lineSet{}
	var stack []string
	var pkg, file string
	var totMissed, totCovered int64
	var totals, sawRoot bool
	var skipped int
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Report{}, fmt.Errorf("codequality.parseJaCoCo: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			switch {
			case len(stack) == 0:
				if name != "report" {
					return Report{}, ErrUnrecognized
				}
				sawRoot = true
			case name == "package":
				pkg = attr(t, "name")
			case name == "sourcefile":
				file = attr(t, "name")
				if pkg != "" && file != "" {
					file = pkg + "/" + file
				}
			case name == "line" && file != "" && stack[len(stack)-1] == "sourcefile":
				n, okN := atoi64(attr(t, "nr"))
				mi, okM := atoi64(attr(t, "mi"))
				ci, okC := atoi64(attr(t, "ci"))
				if !okN || !okM || !okC || n == 0 {
					skipped++
				} else if mi+ci > 0 {
					set.mark(file, int(n), ci > 0)
				}
			case name == "counter" && len(stack) == 1 && attr(t, "type") == "LINE":
				m, okM := atoi64(attr(t, "missed"))
				c, okC := atoi64(attr(t, "covered"))
				if okM && okC {
					totMissed, totCovered, totals = m, c, true
				}
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) > 0 {
				switch stack[len(stack)-1] {
				case "sourcefile":
					file = ""
				case "package":
					pkg = ""
				}
				stack = stack[:len(stack)-1]
			}
		}
	}
	if !sawRoot {
		return Report{}, ErrUnrecognized
	}
	files, lines, covered := set.files()
	r := Report{Format: FormatJaCoCo, Files: files, Lines: lines, Covered: covered, Skipped: skipped}
	if lines == 0 && totals {
		r.Files = nil
		r.Lines, r.Covered, r.TotalsOnly = int(totMissed+totCovered), int(totCovered), true
	}
	return r, nil
}
