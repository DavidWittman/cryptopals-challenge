package set_four

import "testing"

func TestValidateSHA1(t *testing.T) {
	for _, tt := range []struct {
		message  []byte
		mac      []byte
		expected bool
	}{
		{[]byte("this is the message"), []byte{160, 88, 88, 153, 234, 241, 88, 107, 5, 150, 148, 76, 4, 200, 149, 154, 135, 211, 68, 115}, true},
		{[]byte("this is the message"), []byte{166, 92, 42, 124, 250, 241, 88, 107, 5, 150, 148, 76, 4, 200, 142, 154, 135, 211, 68, 115}, false},
	} {
		result := ValidateSHA1(tt.message, tt.mac)
		if result != tt.expected {
			t.Errorf("SHA-1 MAC Validation failed.\nMessage:\t%v\nMAC:\t\t%v", tt.message, tt.mac)
		}
	}
}
