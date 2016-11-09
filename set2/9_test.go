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
		{8, []byte(""), []byte("")},
		{8, []byte(""), []byte("")},
		{8, []byte(""), []byte("")},
		{8, []byte(""), []byte("")},
		{16, []byte(""), []byte("")},
		{16, []byte(""), []byte("")},
		{16, []byte(""), []byte("")},
		{16, []byte(""), []byte("")},
	} {
		result := PKCS7Pad(tt.n, tt.in)
		if !bytes.Equal(result, tt.expected) {
			t.Fatalf("Pad failed. Expected: %v Got: %v", tt.expected, result)
		}
	}
}
