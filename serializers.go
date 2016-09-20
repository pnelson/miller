package miller

import (
	"bytes"
	"encoding/gob"
)

// Serializer represents the ability to encode and decode data.
type Serializer interface {
	// Encode serializes v into a byte slice.
	Encode(v interface{}) ([]byte, error)

	// Decode deserializes b and stores the result in the value pointed to by v.
	Decode(b []byte, v interface{}) error
}

// DefaultSerializer is the default token serializer.
// This serializer leverages encoding/gob for fast serialization.
// See encoding/gob for more information on registering new types.
type DefaultSerializer struct{}

// Encode implements the Serializer interface.
func (s DefaultSerializer) Encode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode implements the Serializer interface.
func (s DefaultSerializer) Decode(b []byte, v interface{}) error {
	buf := bytes.NewBuffer(b)
	return gob.NewDecoder(buf).Decode(v)
}
