// Command oracle scores CVSS 4.0 vectors with github.com/pandatix/go-cvss
// (MIT, v0.6.4), an implementation that does not share code or tables with
// the generated scorer in internal/secassess/cvss4. It was run once to
// produce the committed oracle fixtures; the main module never imports it.
//
//	go run . < vectors.txt          one "vector<TAB>score" line per input line
//	go run . all-base               every one of the 104,976 base vectors, in
//	                                the canonical nested order, "vector<TAB>score"
//
// A vector go-cvss refuses prints "vector<TAB>ERR reason".
package main

import (
	"bufio"
	"fmt"
	"os"

	gocvss40 "github.com/pandatix/go-cvss/40"
)

// base is the value set of each base metric in the order FIRST's calculator
// lists them; the all-base walk nests in this order, AV outermost.
var base = []struct {
	key    string
	values []string
}{
	{"AV", []string{"N", "A", "L", "P"}},
	{"AC", []string{"L", "H"}},
	{"AT", []string{"N", "P"}},
	{"PR", []string{"N", "L", "H"}},
	{"UI", []string{"N", "P", "A"}},
	{"VC", []string{"H", "L", "N"}},
	{"VI", []string{"H", "L", "N"}},
	{"VA", []string{"H", "L", "N"}},
	{"SC", []string{"H", "L", "N"}},
	{"SI", []string{"H", "L", "N"}},
	{"SA", []string{"H", "L", "N"}},
}

func walk(i int, cur string, visit func(string)) {
	if i == len(base) {
		visit(cur)
		return
	}
	for _, v := range base[i].values {
		walk(i+1, cur+"/"+base[i].key+":"+v, visit)
	}
}

func score(out *bufio.Writer, vector string) {
	c, err := gocvss40.ParseVector(vector)
	if err != nil {
		fmt.Fprintf(out, "%s\tERR %v\n", vector, err)
		return
	}
	fmt.Fprintf(out, "%s\t%.1f\n", vector, c.Score())
}

func main() {
	out := bufio.NewWriter(os.Stdout)
	defer func() { _ = out.Flush() }()
	if len(os.Args) > 1 && os.Args[1] == "all-base" {
		walk(0, "CVSS:4.0", func(v string) { score(out, v) })
		return
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	for in.Scan() {
		if line := in.Text(); line != "" {
			score(out, line)
		}
	}
}
