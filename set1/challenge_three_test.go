package set_one

import (
	"testing"
)

func TestDecryptXOR(t *testing.T) {
	result := DecryptXOR("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if result == "" {
		t.Fail()
	}
	t.Log("Decrypted text:", result)
}
