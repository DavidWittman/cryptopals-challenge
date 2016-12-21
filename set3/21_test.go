package set_three

import (
	"testing"
)

func TestMersenneTwister(t *testing.T) {
	expected := []uint64{
		7042061971801565153,
		3971971653833553820,
		6733007059023379977,
		5616813698650337178,
		9458464634160156906,
		1591723812696116321,
	}

	seed := uint64(42)
	mt := NewMersenneTwister()
	mt.Seed(seed)

	for i := 0; i < len(expected); i++ {
		if r := mt.Extract(); r != expected[i] {
			t.Errorf("Wrong number generated. Got: %d, Expected %d.", r, expected[i])
		}
	}

	seed = uint64(18927348912)
	mt = NewMersenneTwister()
	mt.Seed(seed)

	if mt.Extract() == expected[0] {
		t.Errorf("Hey this ain't random bro")
	}
}

func TestMersenneTwisterDefaultSeed(t *testing.T) {
	mt := NewMersenneTwister()
	t.Log(mt.Extract())
	t.Log(mt.Extract())
	t.Log(mt.Extract())
	t.Log(mt.Extract())
	t.Log(mt.Extract())
}
