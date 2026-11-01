package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
)

func ciphers(key []byte) {
	// ruleid: go.weak-cipher
	a, _ := des.NewTripleDESCipher(key)
	// ruleid: go.weak-cipher
	b, _ := rc4.NewCipher(key)
	// ok: go.weak-cipher
	c, _ := aes.NewCipher(key)
	// ok: go.weak-cipher
	g, _ := cipher.NewGCM(c)
	_, _, _ = a, b, g
}
