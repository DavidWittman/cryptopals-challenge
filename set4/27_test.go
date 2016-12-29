package set_four

import (
	"testing"
)

func TestValidASCII(t *testing.T) {
	for _, tt := range []struct {
		input    []byte
		expected bool
	}{
		{[]byte("zomg"), true},
		{[]byte{}, true},
		{[]byte{0, 0, 0, 0}, true},
		{[]byte{0, 1, 2, 3}, true},
		{[]byte{127, 0x41, 0x65}, true},
		{[]byte{0x41, 128}, false},
		{[]byte{255}, false},
		{[]byte{0x45, 0x46, 0x47, 132, 0x48, 0x49}, false},
	} {
		if result := validASCII(tt.input); result != tt.expected {
			t.Errorf("ASCII validation failed (expected %v) for %v", tt.expected, tt.input)
		}
	}
}
