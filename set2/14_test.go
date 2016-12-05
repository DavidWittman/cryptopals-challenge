package set_two

import (
	"testing"
)

func TestBreakHarderECBOracle(t *testing.T) {
	result, err := BreakHarderECBOracle(HarderOracle)
	if err != nil {
		t.Errorf("Error breaking harder oracle: %s", err)
	}
	t.Logf("\n%s", result)
}
