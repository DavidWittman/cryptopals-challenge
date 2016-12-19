package set_three

import (
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func TestGuessFixedNonceCTRKeystreamChallenge20(t *testing.T) {
	ciphers, err := splitDecodeAndEncrypt("./data/20.txt")
	if err != nil {
		t.Errorf("Error preparing input for BreakFixedNonceCTR: %s", err)
	}
	keystream := GuessFixedNonceCTRKeystream(ciphers)
	for _, cipher := range ciphers {
		err := cryptopals.FixedXOR(cipher, keystream[:len(cipher)])
		if err != nil {
			t.Errorf("Error XORing cipher: %s", err)
		}
		t.Log(string(cipher))
	}
}
