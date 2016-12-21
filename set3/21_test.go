package set_three

import (
	"testing"
)

func TestMersenneTwister(t *testing.T) {
	expected := []uint64{
		7042061971801565153,
		17005103146383502316,
		6547901016201289693,
		1862943985907498947,
		1978926124953048649,
		1229322244821217110,
	}

	seed := uint64(42)
	mt := NewMersenneTwister(seed)

	for i := 0; i < len(expected); i++ {
		if r := mt.Extract(); r != expected[i] {
			t.Errorf("Wrong number generated. Got: %d, Expected %d.", r, expected[i])
		}
	}

	seed = uint64(18927348912)
	mt = NewMersenneTwister(seed)

	if mt.Extract() == expected[0] {
		t.Errorf("Hey this ain't random bro")
	}
}
