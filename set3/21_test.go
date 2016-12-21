package set_three

import (
	"testing"
)

func TestMersenneTwister(t *testing.T) {
	expected := []uint32{
		1608637542,
		3421126067,
		4083286876,
		787846414,
		3143890026,
		3348747335,
	}

	seed := uint32(42)
	mt := NewMersenneTwister()
	mt.Seed(seed)

	for i := 0; i < len(expected); i++ {
		if r := mt.Extract(); r != expected[i] {
			t.Errorf("Wrong number generated. Got: %d, Expected %d.", r, expected[i])
		}
	}

	seed = uint32(8912)
	mt = NewMersenneTwister()
	mt.Seed(seed)

	if mt.Extract() == expected[0] {
		t.Errorf("Hey this ain't random bro")
	}
}

func TestMersenneTwisterDefaultSeed(t *testing.T) {
	expected := []uint32{
		3499211612,
		581869302,
		3890346734,
		3586334585,
		545404204,
	}

	// This uses the default seed of 5489
	mt := NewMersenneTwister()

	for i := 0; i < len(expected); i++ {
		if r := mt.Extract(); r != expected[i] {
			t.Errorf("Wrong number generated. Got: %d, Expected %d.", r, expected[i])
		}
	}
}
