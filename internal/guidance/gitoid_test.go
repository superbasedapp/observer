package guidance

import "testing"

// TestGitBlobOID pins GitBlobOID's oid against well-known git blob ids
// (the "git hash-object" values for an empty file and a file containing
// "hello\n", reproducible with `git hash-object` or `printf 'hello\n' |
// git hash-object --stdin`), and pins oidLF against independently
// computed golden values for a CRLF body (see the Python one-liner in
// the table below).
func TestGitBlobOID(t *testing.T) {
	tests := []struct {
		name      string
		body      []byte
		wantOID   string
		wantOIDLF string
	}{
		{
			name:      "empty body — well-known git blob id",
			body:      []byte(""),
			wantOID:   "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
			wantOIDLF: "",
		},
		{
			name:      "LF-only body has no oidLF (nothing to normalize)",
			body:      []byte("hello\n"),
			wantOID:   "ce013625030ba8dba906f756967f9e9ca394464a",
			wantOIDLF: "",
		},
		{
			// Golden values computed independently via:
			//   python3 -c "import hashlib; b=b'a\r\nb\r\n'; \
			//     print(hashlib.sha1(b'blob %d\0' % len(b) + b).hexdigest()); \
			//     lf=b.replace(b'\r\n', b'\n'); \
			//     print(hashlib.sha1(b'blob %d\0' % len(lf) + lf).hexdigest())"
			name:      "CRLF body gets both a raw and an LF-normalized oid",
			body:      []byte("a\r\nb\r\n"),
			wantOID:   "c30dea8a3641ea99b125d04d599d843712292759",
			wantOIDLF: "422c2b7ab3b3c668038da977e4e93a5fc623169c",
		},
		{
			// A lone "\r" with no following "\n" is not a CRLF pair, so
			// this must NOT trigger normalization — oidLF stays "".
			// Golden oid via:
			//   python3 -c "import hashlib; b=b'a\rb'; \
			//     print(hashlib.sha1(b'blob %d\0' % len(b) + b).hexdigest())"
			name:      "single CR with no matching LF is not treated as CRLF",
			body:      []byte("a\rb"),
			wantOID:   "2fe40ba389048204a83882bc3f75bf2188db6d47",
			wantOIDLF: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOID, gotOIDLF := GitBlobOID(tt.body)
			if gotOID != tt.wantOID {
				t.Errorf("GitBlobOID(%q) oid = %q, want %q", tt.body, gotOID, tt.wantOID)
			}
			if gotOIDLF != tt.wantOIDLF {
				t.Errorf("GitBlobOID(%q) oidLF = %q, want %q", tt.body, gotOIDLF, tt.wantOIDLF)
			}
		})
	}
}

// TestGitBlobOIDDeterministic checks that GitBlobOID is a pure function
// of body — same input, same output, called twice — and that oid is
// always well-formed lowercase hex sha1 regardless of body shape.
func TestGitBlobOIDDeterministic(t *testing.T) {
	bodies := [][]byte{
		[]byte(""),
		[]byte("hello\n"),
		[]byte("a\r\nb\r\n"),
		[]byte("binary\x00bytes\xffhere"),
	}
	for _, body := range bodies {
		oid1, oidLF1 := GitBlobOID(body)
		oid2, oidLF2 := GitBlobOID(body)
		if oid1 != oid2 || oidLF1 != oidLF2 {
			t.Fatalf("GitBlobOID(%q) not deterministic: (%q,%q) vs (%q,%q)", body, oid1, oidLF1, oid2, oidLF2)
		}
		if len(oid1) != 40 {
			t.Errorf("GitBlobOID(%q) oid = %q, want 40 lowercase hex characters", body, oid1)
		}
		for _, r := range oid1 {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				t.Errorf("GitBlobOID(%q) oid = %q, want only lowercase hex digits", body, oid1)
				break
			}
		}
	}
}
