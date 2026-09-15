package migrate

import (
	"strings"
	"testing"
)

func sp(rhs string, segs ...string) ScalarPatch { return ScalarPatch{Path: segs, RHS: rhs} }

// TestPatchScalars is the hostile-input table for the Tier-A surgical
// editor (plan P1-4): comments, quotes, inline tables, arrays, multi-line
// strings, dotted keys, CRLF, empty files, array tables.
func TestPatchScalars(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		patches []ScalarPatch
		want    string   // expected text when applied
		unsafe  []string // expected Unsafe paths (text must be unchanged)
	}{
		{
			name:    "replace keeps indent, above-comment and inline comment",
			in:      "# top comment\n[observer]\n  # why we warn\n  log_level = \"warn\" # keep me\n  db_path = \"/x\"\n",
			patches: []ScalarPatch{sp(`"debug"`, "observer", "log_level")},
			want:    "# top comment\n[observer]\n  # why we warn\n  log_level = \"debug\" # keep me\n  db_path = \"/x\"\n",
		},
		{
			name:    "hash inside the existing quoted value is not a comment",
			in:      "[observer]\nlog_level = \"a # b\" # real\n",
			patches: []ScalarPatch{sp(`"c"`, "observer", "log_level")},
			want:    "[observer]\nlog_level = \"c\" # real\n",
		},
		{
			name:    "hash inside the NEW quoted value survives verbatim",
			in:      "[observer]\nlog_level = \"warn\"\n",
			patches: []ScalarPatch{sp(`"x # y = z"`, "observer", "log_level")},
			want:    "[observer]\nlog_level = \"x # y = z\"\n",
		},
		{
			name:    "equals sign inside the existing value",
			in:      "[proxy]\nanthropic_upstream = \"https://h/?a=b\"\n",
			patches: []ScalarPatch{sp(`"https://h/?c=d"`, "proxy", "anthropic_upstream")},
			want:    "[proxy]\nanthropic_upstream = \"https://h/?c=d\"\n",
		},
		{
			name:    "insert after the table's last direct key, before the next table",
			in:      "[terminal]\nenabled = true\n\n[terminal.launch]\nallow_shell = false\n",
			patches: []ScalarPatch{sp("12", "terminal", "max_concurrent")},
			want:    "[terminal]\nenabled = true\nmax_concurrent = 12\n\n[terminal.launch]\nallow_shell = false\n",
		},
		{
			name:    "insert creates the table at EOF",
			in:      "[observer]\nlog_level = \"warn\"\n",
			patches: []ScalarPatch{sp("true", "terminal", "sandbox", "enabled")},
			want:    "[observer]\nlog_level = \"warn\"\n\n[terminal.sandbox]\nenabled = true\n",
		},
		{
			name:    "empty file",
			in:      "",
			patches: []ScalarPatch{sp("9", "terminal", "max_concurrent")},
			want:    "[terminal]\nmax_concurrent = 9",
		},
		{
			name:    "dotted key at root is found and replaced in place",
			in:      "observer.watch.poll_interval_seconds = 5 # poll\n",
			patches: []ScalarPatch{sp("10", "observer", "watch", "poll_interval_seconds")},
			want:    "observer.watch.poll_interval_seconds = 10 # poll\n",
		},
		{
			name:    "dotted key inside a table keeps its spelling",
			in:      "[observer]\nwatch.poll_interval_seconds = 5\n",
			patches: []ScalarPatch{sp("10", "observer", "watch", "poll_interval_seconds")},
			want:    "[observer]\nwatch.poll_interval_seconds = 10\n",
		},
		{
			name:    "quoted key keeps its spelling",
			in:      "[profiles]\n\"default\" = \"a\"\n",
			patches: []ScalarPatch{sp(`"b"`, "profiles", "default")},
			want:    "[profiles]\n\"default\" = \"b\"\n",
		},
		{
			name:    "CRLF preserved",
			in:      "[observer]\r\nlog_level = \"warn\"\r\n",
			patches: []ScalarPatch{sp(`"info"`, "observer", "log_level"), sp("7", "terminal", "max_concurrent")},
			want:    "[observer]\r\nlog_level = \"info\"\r\n\r\n[terminal]\r\nmax_concurrent = 7\r\n",
		},
		{
			name:    "nested indent style matched on insert",
			in:      "[observer]\n  log_level = \"warn\"\n  [observer.watch]\n    poll_interval_seconds = 5\n",
			patches: []ScalarPatch{sp("20", "observer", "watch", "max_file_size_mb")},
			want:    "[observer]\n  log_level = \"warn\"\n  [observer.watch]\n    poll_interval_seconds = 5\n    max_file_size_mb = 20\n",
		},
		{
			name:    "header with an inline comment still matches",
			in:      "[observer] # the block\nlog_level = \"warn\"\n",
			patches: []ScalarPatch{sp(`"info"`, "observer", "log_level")},
			want:    "[observer] # the block\nlog_level = \"info\"\n",
		},
		// ---- refusals: text must come back byte-identical ----
		{
			name:    "existing array value is unsafe",
			in:      "[terminal.launch]\nallowed_tools = [\"a\", \"b\"]\n",
			patches: []ScalarPatch{sp(`"x"`, "terminal", "launch", "allowed_tools")},
			unsafe:  []string{"terminal.launch.allowed_tools"},
		},
		{
			name:    "existing inline table value is unsafe",
			in:      "[observer]\nwatch = { poll_interval_seconds = 5 }\n",
			patches: []ScalarPatch{sp("10", "observer", "watch")},
			unsafe:  []string{"observer.watch"},
		},
		{
			name:    "insert under an inline-table parent is unsafe",
			in:      "[observer]\nwatch = { poll_interval_seconds = 5 }\n",
			patches: []ScalarPatch{sp("10", "observer", "watch", "max_file_size_mb")},
			unsafe:  []string{"observer.watch.max_file_size_mb"},
		},
		{
			name:    "existing multi-line string is unsafe",
			in:      "[guard.rules]\nuser_policy = \"\"\"\nline\n\"\"\"\n",
			patches: []ScalarPatch{sp(`"x"`, "guard", "rules", "user_policy")},
			unsafe:  []string{"guard.rules.user_policy"},
		},
		{
			name:    "insert under an array-of-tables parent is unsafe",
			in:      "[[experiments]]\nname = \"a\"\n",
			patches: []ScalarPatch{sp(`"b"`, "experiments", "class")},
			unsafe:  []string{"experiments.class"},
		},
		{
			name:    "new rhs that is not a scalar is refused",
			in:      "[observer]\nlog_level = \"warn\"\n",
			patches: []ScalarPatch{sp(`["a"]`, "observer", "log_level")},
			unsafe:  []string{"observer.log_level"},
		},
		{
			name:    "new rhs with a newline is refused",
			in:      "[observer]\nlog_level = \"warn\"\n",
			patches: []ScalarPatch{sp("\"a\nb\"", "observer", "log_level")},
			unsafe:  []string{"observer.log_level"},
		},
		{
			name:    "one unsafe patch refuses the whole batch",
			in:      "[observer]\nlog_level = \"warn\"\n[terminal.launch]\nallowed_tools = []\n",
			patches: []ScalarPatch{sp(`"info"`, "observer", "log_level"), sp(`"x"`, "terminal", "launch", "allowed_tools")},
			unsafe:  []string{"terminal.launch.allowed_tools"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := PatchScalars(c.in, c.patches)
			if len(c.unsafe) > 0 {
				if res.Text != c.in {
					t.Fatalf("unsafe batch must leave text untouched:\n got: %q\nwant: %q", res.Text, c.in)
				}
				if strings.Join(res.Unsafe, ",") != strings.Join(c.unsafe, ",") {
					t.Fatalf("Unsafe = %v; want %v", res.Unsafe, c.unsafe)
				}
				if res.Reason == "" || len(res.Applied) != 0 {
					t.Fatalf("unsafe result must carry a reason and no Applied: %+v", res)
				}
				return
			}
			if len(res.Unsafe) > 0 {
				t.Fatalf("unexpected refusal %v: %s", res.Unsafe, res.Reason)
			}
			if res.Text != c.want {
				t.Fatalf("text mismatch:\n got: %q\nwant: %q", res.Text, c.want)
			}
			if len(res.Applied) != len(c.patches) {
				t.Fatalf("Applied = %v; want %d entries", res.Applied, len(c.patches))
			}
		})
	}
}

func TestSplitInlineComment(t *testing.T) {
	cases := []struct{ in, value, comment string }{
		{`"a"`, `"a"`, ""},
		{`"a" # c`, `"a"`, "# c"},
		{`"a # b" # c`, `"a # b"`, "# c"},
		{`'a # b'`, `'a # b'`, ""},
		{`5 #`, `5`, "#"},
		{`true#x`, `true`, "#x"},
	}
	for _, c := range cases {
		v, cm := splitInlineComment(c.in)
		if v != c.value || cm != c.comment {
			t.Errorf("splitInlineComment(%q) = %q,%q; want %q,%q", c.in, v, cm, c.value, c.comment)
		}
	}
}
