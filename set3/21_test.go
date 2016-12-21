package set_three

import (
	"testing"
)

func TestMersenneTwister(t *testing.T) {
	seed := uint64(42)
	mt := NewMersenneTwister(seed)
	t.Log(mt.Extract())
	t.Log(mt.Extract())
	t.Log(mt.Extract())
	t.Log(mt.Extract())
	t.Log(mt.Extract())
	t.Log(mt.Extract())
}
