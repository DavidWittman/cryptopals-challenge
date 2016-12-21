package set_three

import (
	"testing"
)

func TestMersenneTwister(t *testing.T) {
	seed := uint64(42)
	t.Log(NewMersenneTwister(seed))
}
