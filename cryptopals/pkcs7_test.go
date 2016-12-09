package cryptopals

import (
	"bytes"
	"testing"
)

func TestPKCS7Pad(t *testing.T) {
	for _, tt := range []struct {
		n        int
		input    []byte
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
		result := PKCS7Pad(tt.n, tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("Pad failed. Expected: %v Got: %v", tt.expected, result)
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

func TestPKCS7Unpad(t *testing.T) {
	for _, tt := range []struct {
		input    []byte
		expected []byte
	}{
		{[]byte("\x08\x08\x08\x08\x08\x08\x08\x08"), []byte("")},
		{[]byte("a\x07\x07\x07\x07\x07\x07\x07"), []byte("a")},
		{[]byte("ab\x06\x06\x06\x06\x06\x06"), []byte("ab")},
		{[]byte("abc\x05\x05\x05\x05\x05"), []byte("abc")},
		{[]byte("abcd\x04\x04\x04\x04"), []byte("abcd")},
		{[]byte("abcde\x03\x03\x03"), []byte("abcde")},
		{[]byte("abcdef\x02\x02"), []byte("abcdef")},
		{[]byte("abcdefg\x01"), []byte("abcdefg")},
		{[]byte("abcdefgh\x08\x08\x08\x08\x08\x08\x08\x08"), []byte("abcdefgh")},
	} {
		result, _ := PKCS7Unpad(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("Pad failed. Expected: %v Got: %v", tt.expected, result)
		}
	}

}

func TestIsPKCS7Padded(t *testing.T) {
	for _, tt := range []struct {
		input    []byte
		expected bool
	}{
		{[]byte("\x08\x08\x08\x08\x08\x08\x08\x08"), true},
		{[]byte("a\x07\x07\x07\x07\x07\x07\x07"), true},
		{[]byte("ab\x06\x06\x06\x06\x06\x06"), true},
		{[]byte("abc\x05\x05\x05\x05\x05"), true},
		{[]byte("abcd\x04\x04\x04\x04"), true},
		{[]byte("abcde\x03\x03\x03"), true},
		{[]byte("abcdef\x02\x02"), true},
		{[]byte("abcdefg\x01"), true},
		{[]byte("abcdefgh\x08\x08\x08\x08\x08\x08\x08\x08"), true},
		{[]byte("abcdefg\x01\x01"), false},
		{[]byte("abcdefg\x02"), false},
		{[]byte("abcdefga"), false},
		{[]byte("abcdef\x01"), false}, // Uneven
		{[]byte("abcdefg\x03\x02\x03"), false},
		{[]byte("abcdefg\x01a\x03"), false},
		{[]byte("abcdefg\x01\x01\x03"), false},
	} {
		result := IsPKCS7Padded(tt.input)
		if result != tt.expected {
			t.Errorf("Pad detection failed for %v.\tExpected: %v, Got: %v", tt.input, tt.expected, result)
		}
	}

}
