package set_three

import (
	"testing"
)

// This was previously generated with GenerateRandomInt
const randomInt = 606774834

func TestGenerateRandomInt(t *testing.T) {
	// Skip this test if we already have a random integer which was generated
	// by this function
	if randomInt != 0 {
		t.Skip("Using previously generated random integer")
	}
	i := GenerateRandomInt()
	t.Logf("Generated random integer: %d", i)
}

func TestFindSeed(t *testing.T) {
	result := FindSeed(randomInt)

	mt := NewMersenneTwister()
	mt.Seed(result)

	if r := mt.Extract(); r != randomInt {
		t.Errorf("Incorrect seed found: %d", result)
	}
}
