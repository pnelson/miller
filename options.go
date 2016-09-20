package miller

// Option represents a functional option for configuration.
type Option func(*Token)

// SetSerializer sets the serializer for token signing and verifying.
func SetSerializer(s Serializer) Option {
	return func(t *Token) {
		t.serializer = s
	}
}
