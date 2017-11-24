package set_five

import (
	"bytes"
	"math/big"
	"testing"
)

func TestModInverse(t *testing.T) {
	result := new(big.Int).ModInverse(big.NewInt(17), big.NewInt(3120))
	if result.Cmp(big.NewInt(2753)) != 0 {
		t.Errorf("Bad result from ModInverse: %v", result)
	}
}

func TestRSAGenerate(t *testing.T) {
	_, err := RSAGenerate()
	if err != nil {
		t.Error(err)
	}
}

func TestRSAEncryptDecrypt(t *testing.T) {
	input := []byte("GO NINJA GO NINJA GO")
	for i := 0; i < 10; i++ {
		key, err := RSAGenerate()
		if err != nil {
			t.Errorf("Error generating RSA key: %s", err)
		}

		result := RSADecrypt(RSAEncrypt(input, &key.PublicKey), key)
		if !bytes.Equal(result, input) {
			t.Errorf("Decryption failed: %q", result)
		}
	}
}
