package mcprelay

import (
	"crypto/rand"
	"io"
)

// randReader is the package's randomness source (crypto/rand; tests may
// not replace it - ids stay unpredictable everywhere).
var randReader io.Reader = rand.Reader
