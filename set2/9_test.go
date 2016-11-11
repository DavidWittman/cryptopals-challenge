package set_two

import (
	"bytes"
	"testing"
)

func TestPKCS7Pad(t *testing.T) {
	for _, tt := range []struct {
		n        int
		in       []byte
		expected []byte
	}{
		{8, []byte(""), []byte("\x08\x08\x08\x08\x08\x08\x08\x08")},
		{8, []byte("a"), []byte("a\x07\x07\x07\x07\x07\x07\x07")},
		{8, []byte("ab"), []byte("ab\x06\x06\x06\x06\x06\x06")},
		{8, []byte("abc"), []byte("abc\x05\x05\x05\x05\x05")},
		{8, []byte("abcd"), []byte("abcd\x04\x04\x04\x04")},
		{8, []byte("abcde"), []byte("abcde\x03\x03\x03")},
		{8, []byte("abcdef"), []byte("abcdef\x02\x02")},
		{8, []byte("abcdefg"), []byte("abcdefg\x01")},
		{8, []byte("abcdefgh"), []byte("abcdefgh\x08\x08\x08\x08\x08\x08\x08\x08")},
		{8, []byte("abcdefgh1"), []byte("abcdefgh1\x07\x07\x07\x07\x07\x07\x07")},
		{16, []byte(""), []byte("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")},
		{16, []byte("a"), []byte("a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f")},
		{20, []byte("YELLOW SUBMARINE"), []byte("YELLOW SUBMARINE\x04\x04\x04\x04")},
	} {
		result := PKCS7Pad(tt.n, tt.in)
		if !bytes.Equal(result, tt.expected) {
			t.Fatalf("Pad failed. Expected: %v Got: %v", tt.expected, result)
		}
	}
}

func TestPKCS7PadPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("PKCS7Pad did not panic due to invalid block length")
		}
	}()
	_ = PKCS7Pad(256, []byte("zomg"))
}
