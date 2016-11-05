package set_one

import "testing"

func TestCountBits(t *testing.T) {
	if countBits(byte(0x8F)) != 5 {
		t.Fail()
	}
	if countBits(byte(0x00)) != 0 {
		t.Fail()
	}
	if countBits(byte(0xFF)) != 8 {
		t.Fail()
	}
}

func TestHammingDistance(t *testing.T) {
	if hammingDistance("this is a test", "wokka wokka!!!") != 37 {
		t.Fail()
	}
}
