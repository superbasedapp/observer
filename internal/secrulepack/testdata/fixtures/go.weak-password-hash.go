package auth

import (
	"crypto/md5"
	"crypto/sha256"

	"golang.org/x/crypto/bcrypt"
)

type User struct{ Password, Salt string }

func store(u User, password string, body []byte) {
	// ruleid: go.weak-password-hash
	a := md5.Sum([]byte(password))
	// ruleid: go.weak-password-hash
	b := sha256.Sum256([]byte(u.Salt + u.Password))
	// ok: go.weak-password-hash
	c := sha256.Sum256(body)
	// ok: go.weak-password-hash
	d, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_, _, _, _ = a, b, c, d
}
