// Package miller implements tamper resistant message signing and verification.
package miller

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"strings"
)

// Token represents the configuration for signing and
// verifying token values.
type Token struct {
	tag        string
	key        []byte
	serializer Serializer
}

// DefaultTag represents the default key derivation tag.
const DefaultTag = "miller"

// sep represents the token part separator.
const sep = "."

var (
	// ErrInvalid represents an unprocessable token error.
	ErrInvalid = errors.New("miller: invalid token")

	// ErrSignature represents an invalid signature error.
	ErrSignature = errors.New("miller: invalid signature")
)

// New returns a new Token.
func New(tag string, key []byte, opts ...Option) *Token {
	t := &Token{
		tag:        tag,
		key:        key,
		serializer: DefaultSerializer{},
	}
	for _, option := range opts {
		option(t)
	}
	return t
}

// Sign returns a token comprised of the serialized contents
// of v and the cryptographic signature later used to verify
// that the payload has not been tampered.
func (t *Token) Sign(v interface{}) (string, error) {
	b, err := t.serializer.Encode(v)
	if err != nil {
		return "", err
	}
	token := encode(b) + sep + encode(hash(b, t.deriveKey()))
	return token, nil
}

// Verify parses a token and returns an error if the token or signature
// is invalid. If the signature is valid, the decoded payload is
// stored in the value pointed to by v.
func (t *Token) Verify(token string, v interface{}) error {
	i := strings.Index(token, sep)
	if i == -1 {
		return ErrInvalid
	}
	b, err := decode(token[:i])
	if err != nil {
		return ErrInvalid
	}
	sig, err := decode(token[i+1:])
	if err != nil {
		return ErrInvalid
	}
	mac := hash(b, t.deriveKey())
	if !hmac.Equal(mac, sig) {
		return ErrSignature
	}
	return t.serializer.Decode(b, v)
}

// deriveKey returns a new secret key derived from the
// configured tag and key.
func (t *Token) deriveKey() []byte {
	return hash([]byte(t.tag), t.key)
}

// keySize represents the byte size for generated keys.
const keySize = 32

// GenerateKey returns a 256-bit key suitable for hashing with.
func GenerateKey() []byte {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		// Cryptographic pseudo-random number generation should not
		// fail, but if it does, it is probably worth the panic.
		panic(err)
	}
	return key
}
