package set_five

import (
	"math/big"
	"testing"
)

func TestRSAGenerate(t *testing.T) {
	_, err := RSAGenerate()
	if err != nil {
		t.Error(err)
	}
}

func TestModInverse(t *testing.T) {
	result := new(big.Int).ModInverse(big.NewInt(17), big.NewInt(3120))
	if result.Cmp(big.NewInt(2753)) != 0 {
		t.Errorf("Bad result from ModInverse: %v", result)
	}
}
