package miller

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
)

var b64 = base64.RawURLEncoding

// decode returns the padding-free URL-safe base64 decoded byte slice.
func decode(s string) ([]byte, error) {
	return b64.DecodeString(s)
}

// encode returns a base64 padding-free URL-safe encoded string.
func encode(b []byte) string {
	return b64.EncodeToString(b)
}

// hash returns the HMAC SHA-512/256 of b with key.
func hash(b, key []byte) []byte {
	h := hmac.New(sha512.New512_256, b)
	h.Write(key)
	return h.Sum(nil)
}
