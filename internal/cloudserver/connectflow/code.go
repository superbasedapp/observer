package connectflow

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// codeLetters is the user code's letter alphabet: consonants without I and O,
// so a code is never a word and never confusable with a digit.
const codeLetters = "BCDFGHJKLMNPQRSTVWXZ"

// codeDigits is the user code's digit alphabet.
const codeDigits = "0123456789"

// codeHalf is the number of letters, and of digits, in a code.
const codeHalf = 4

// ErrUserCode is returned for a typed code that cannot be a user code.
var ErrUserCode = errors.New("connectflow: not a connect code")

// NewUserCode mints a code like KTRW-4821 from r (crypto/rand.Reader in
// production). Each character is drawn by rejection sampling, so every code
// is equally likely.
func NewUserCode(r io.Reader) (string, error) {
	var b strings.Builder
	b.Grow(2*codeHalf + 1)
	if err := drawInto(&b, r, codeLetters, codeHalf); err != nil {
		return "", fmt.Errorf("connectflow.NewUserCode: %w", err)
	}
	b.WriteByte('-')
	if err := drawInto(&b, r, codeDigits, codeHalf); err != nil {
		return "", fmt.Errorf("connectflow.NewUserCode: %w", err)
	}
	return b.String(), nil
}

// drawInto appends n characters of alphabet to b, drawn uniformly from r.
func drawInto(b *strings.Builder, r io.Reader, alphabet string, n int) error {
	limit := 256 - 256%len(alphabet)
	var one [1]byte
	for got := 0; got < n; {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return err
		}
		if int(one[0]) >= limit {
			continue
		}
		b.WriteByte(alphabet[int(one[0])%len(alphabet)])
		got++
	}
	return nil
}

// NormalizeUserCode turns what a person typed into the stored form
// (KTRW-4821): case-insensitive, spaces and hyphens ignored. It returns
// ErrUserCode for anything that cannot be a code.
func NormalizeUserCode(typed string) (string, error) {
	var compact strings.Builder
	for _, c := range strings.ToUpper(typed) {
		if c == ' ' || c == '-' || c == '\t' {
			continue
		}
		if compact.Len() >= 2*codeHalf {
			return "", ErrUserCode
		}
		compact.WriteRune(c)
	}
	s := compact.String()
	if len(s) != 2*codeHalf {
		return "", ErrUserCode
	}
	for i := 0; i < codeHalf; i++ {
		if !strings.ContainsRune(codeLetters, rune(s[i])) || !strings.ContainsRune(codeDigits, rune(s[codeHalf+i])) {
			return "", ErrUserCode
		}
	}
	return s[:codeHalf] + "-" + s[codeHalf:], nil
}
