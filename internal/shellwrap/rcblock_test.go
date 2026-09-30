package shellwrap

import (
	"errors"
	"strings"
	"testing"
)

const testBody = "sbo_shim_dir='/h/.observer/shims'\nexport PATH\n"

// TestInsertRemoveRoundTripIsByteExact pins the undo contract: removing the
// block restores every original byte, whatever the file looked like.
func TestInsertRemoveRoundTripIsByteExact(t *testing.T) {
	cases := []struct {
		name    string
		content string
		exists  bool
	}{
		{"missing file", "", false},
		{"empty existing file", "", true},
		{"trailing newline", "export A=1\n", true},
		{"no trailing newline", "export A=1", true},
		{"crlf", "$x = 1\r\n$y = 2\r\n", true},
		{"crlf no trailing newline", "$x = 1\r\n$y = 2", true},
		{"blank lines at end", "a\n\n\n", true},
		{"unicode and tabs", "\talias ll='ls -l' # héllo\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, err := InsertBlock(tc.content, testBody, tc.exists)
			if err != nil {
				t.Fatalf("InsertBlock: %v", err)
			}
			if !strings.HasPrefix(in, tc.content) {
				t.Fatalf("insert must only append: got %q", in)
			}
			again, err := InsertBlock(in, testBody, true)
			if err != nil || again != in {
				t.Fatalf("second insert not idempotent (err=%v):\n%q\n%q", err, in, again)
			}
			res, err := RemoveBlock(in)
			if err != nil {
				t.Fatalf("RemoveBlock: %v", err)
			}
			if !res.Found || res.Content != tc.content {
				t.Fatalf("round trip: found=%v\nwant %q\ngot  %q", res.Found, tc.content, res.Content)
			}
			if res.DeleteFile != !tc.exists {
				t.Fatalf("DeleteFile = %v, want %v", res.DeleteFile, !tc.exists)
			}
		})
	}
}

func TestInsertBlockMatchesFileLineEnding(t *testing.T) {
	out, err := InsertBlock("a\r\n", "x\ny\n", true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Fatalf("a CRLF file must get CRLF block lines: %q", out)
	}
}

func TestInsertBlockReplacesInPlaceAndKeepsSurroundings(t *testing.T) {
	orig := "before\n"
	in, _ := InsertBlock(orig, "old\n", true)
	withAfter := in + "after # the operator added this later\n"
	next, err := InsertBlock(withAfter, "new\n", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(next, "before\n") || !strings.HasSuffix(next, "after # the operator added this later\n") {
		t.Fatalf("surroundings changed: %q", next)
	}
	if strings.Contains(next, "old") || !strings.Contains(next, "new") {
		t.Fatalf("body not replaced: %q", next)
	}
	res, _ := RemoveBlock(next)
	if res.Content != orig+"after # the operator added this later\n" {
		t.Fatalf("remove after later edits: %q", res.Content)
	}
	if res.DeleteFile {
		t.Fatal("a file with operator content must never be deleted")
	}
}

func TestCreatedFileWithLaterContentIsKept(t *testing.T) {
	in, _ := InsertBlock("", testBody, false)
	res, err := RemoveBlock(in + "export B=2\n")
	if err != nil {
		t.Fatal(err)
	}
	if res.DeleteFile || res.Content != "export B=2\n" {
		t.Fatalf("got %+v", res)
	}
}

func TestMalformedBlocksAreRefused(t *testing.T) {
	cases := map[string]string{
		"begin without end": "a\n" + BlockBegin + "\nx\n",
		"end without begin": "a\n" + BlockEnd + "\n",
		"two blocks":        BlockBegin + "\n" + BlockEnd + "\n" + BlockBegin + "\n" + BlockEnd + "\n",
		"end before begin":  BlockEnd + "\n" + BlockBegin + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := InsertBlock(content, testBody, true); !errors.Is(err, ErrMalformedBlock) {
				t.Fatalf("InsertBlock err = %v", err)
			}
			res, err := RemoveBlock(content)
			if !errors.Is(err, ErrMalformedBlock) || res.Content != content {
				t.Fatalf("RemoveBlock err = %v content changed=%v", err, res.Content != content)
			}
		})
	}
}

func TestRemoveBlockAbsentIsNoop(t *testing.T) {
	res, err := RemoveBlock("export A=1\n")
	if err != nil || res.Found || res.Content != "export A=1\n" || res.DeleteFile {
		t.Fatalf("got %+v err %v", res, err)
	}
}

func TestBlockBodyRoundTrip(t *testing.T) {
	in, _ := InsertBlock("x\r\n", testBody, true)
	body, found, err := BlockBody(in)
	if err != nil || !found || body != testBody {
		t.Fatalf("BlockBody = %q found=%v err=%v", body, found, err)
	}
}
