package set_four

import "testing"

func TestSHA256HMAC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	message := []byte("this is just another message")
	expected := "c6b7657868cc5bc8745121891eedb34e4ea44145ef78ba776f7775a41a64da32"

	result := SHA256HMAC(key, message)
	if result != expected {
		t.Errorf("Incorrect HMAC generated.\nExpected:\t%v\nGot:\t\t%v", expected, result)
	}
}

func TestInsecureCompare(t *testing.T) {
	// Not testing any of the timing stuff here
	for _, tt := range []struct {
		a, b     []byte
		expected bool
	}{
		{[]byte("yellow"), []byte("yellow"), true},
		{[]byte("submarine"), []byte("sub"), false},
		{[]byte("we all live"), []byte("we all love"), false},
	} {
		if result := InsecureCompare(tt.a, tt.b, uint8(1)); result != tt.expected {
			t.Errorf("InsecureCompare failed for %+v", tt)
		}
	}
}
