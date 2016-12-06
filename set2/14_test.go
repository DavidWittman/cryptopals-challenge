package set_two

import (
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func NewFakeOracle(prefix string) func([]byte) []byte {
	return func(input []byte) []byte {
		input = append([]byte(prefix), input...)
		result, _ := cryptopals.EncryptAESECB(input, cryptopals.RANDOM_KEY)
		return result
	}
}

func TestBreakHarderECBOracle(t *testing.T) {
	result, err := BreakHarderECBOracle(HarderOracle)
	if err != nil {
		t.Errorf("Error breaking harder oracle: %s", err)
	}
	t.Logf("\n%s", result)
}

func TestFindRandomPrefixLength(t *testing.T) {
	tests := []string{
		"",
		"z",
		"zomg",
		"zomgwtf",
		"zomgwtfbbq",
		"oiajefoijewoifaoijfoasjdfoijsaodijfoijfioaejwfoiawjoijaofajio",
	}
	for i, test := range tests {
		fakeOracle := NewFakeOracle(test)
		result := FindRandomPrefixLength(fakeOracle, 16)
		if result != len(tests[i]) {
			t.Errorf("Incorrect prefix length: Expected: %d, Got: %d", len(tests[i]), result)
		}
	}
}
