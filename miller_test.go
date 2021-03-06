package miller

import (
	"bytes"
	"testing"
)

var secret = []byte("secret")

func TestNew(t *testing.T) {
	s := New(DefaultTag, secret)
	if s.tag == "" {
		t.Fatal("should set defaults")
	}
}

func TestSignVerify(t *testing.T) {
	const data = "foo"
	m := New(DefaultTag, secret)
	token, err := m.Sign(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "ImZvbyIK.0rVD2UDu90K_qTLxLivHenuSEYdcWu6blP3ezwHLiyQ"
	if token != want {
		t.Fatalf("Sign\nhave %q\nwant %q", token, want)
	}
	var s string
	err = m.Verify(token, &s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != data {
		t.Fatalf("Verify\nhave %q\nwant %q", s, data)
	}
	token = token[:len(token)-1] // tampered
	err = m.Verify(token, &s)
	if err != ErrSignature {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyErrInvalid(t *testing.T) {
	m := New(DefaultTag, secret)
	err := m.Verify("invalid", nil)
	if err != ErrInvalid {
		t.Fatal("should return invalid token error")
	}
}

func TestVerifyErrInvalidDecode(t *testing.T) {
	m := New(DefaultTag, secret)
	err := m.Verify("invalid.token", nil)
	if err != ErrInvalid {
		t.Fatal("should return invalid token error")
	}
}

func TestSignVerifyTags(t *testing.T) {
	const data = "foo"
	m1 := New("tag1", secret)
	t1, err := m1.Sign(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m2 := New("tag2", secret)
	t2, err := m2.Sign(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if t1 == t2 {
		t.Fatalf("should return namespaced tokens")
	}
}

func TestGenerateKey(t *testing.T) {
	a := GenerateKey()
	for i := 0; i < 10; i++ {
		b := GenerateKey()
		if bytes.Equal(a, b) {
			t.Fatal("should not generate duplicate key")
		}
		if len(b) != keySize {
			t.Fatal("should be a standardized length")
		}
	}
}
