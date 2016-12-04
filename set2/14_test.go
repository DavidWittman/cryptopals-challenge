package set_two

import (
	"testing"
)

func TestBreakHarderOracle(t *testing.T) {
	_, err := BreakHarderOracle(HarderOracle)
	if err != nil {
		t.Errorf("Error breaking harder oracle: %s", err)
	}
}

func TestDetermineUnknownStringSize(t *testing.T) {
	result := DetermineUnknownStringSize(HarderOracle, 16)
	if result != 144 {
		t.Errorf("Determined incorrect size. Expected: 144, Got: %d", result)
	}
}
