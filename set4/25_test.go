package set_four

import (
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func TestEncryptFileCTR(t *testing.T) {
	cipher, err := encryptFileCTR("./data/25_plain.txt", cryptopals.RANDOM_KEY, 0)
	if err != nil {
		t.Errorf("Error encrypting file: %s", err)
	}
	if len(cipher) != 2883 {
		t.Errorf("Ciphertext length incorrect: Got: %d, Expected: 2883", len(cipher))
	}
}
