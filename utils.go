package miller

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
)

// decode returns the padding-free URL-safe base64 decoded byte slice.
func decode(b []byte) ([]byte, error) {
	pad := bytes.Repeat([]byte("="), (-len(b)%4+4)%4)
	padded := make([]byte, len(b)+len(pad))
	copy(padded, b)
	copy(padded[len(b):], pad)
	rv := make([]byte, base64.URLEncoding.DecodedLen(len(padded)))
	n, err := base64.URLEncoding.Decode(rv, padded)
	if err != nil {
		return nil, err
	}
	return rv[:n], nil
}

// encode returns a base64 padding-free URL-safe encoded byte slice.
func encode(b []byte) []byte {
	rv := make([]byte, base64.URLEncoding.EncodedLen(len(b)))
	base64.URLEncoding.Encode(rv, b)
	return bytes.TrimRight(rv, "=")
}

// hash returns the HMAC SHA-512/256 of b with key.
func hash(b, key []byte) []byte {
	h := hmac.New(sha512.New512_256, b)
	h.Write(key)
	return h.Sum(nil)
}
