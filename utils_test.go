package miller

import "testing"

func TestEncode(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{"foo", "Zm9v"},      // 0x =
		{"hello", "aGVsbG8"}, // 1x =
		{"a", "YQ"},          // 2x =
	}
	for i, tt := range tests {
		out := encode([]byte(tt.in))
		if string(out) != tt.out {
			t.Errorf("%d. encode(%q)\nhave %s\nwant %s", i, tt.in, out, tt.out)
		}
	}
}

func TestDecode(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{"Zm9v", "foo"},      // 0x =
		{"aGVsbG8", "hello"}, // 1x =
		{"YQ", "a"},          // 2x =
	}
	for i, tt := range tests {
		out, err := decode([]byte(tt.in))
		if err != nil {
			t.Errorf("%d. unexpected error: %s", i, err)
			continue
		}
		if string(out) != tt.out {
			t.Errorf("%d. decode(%q)\nhave %s\nwant %s", i, tt.in, out, tt.out)
		}
	}
}
