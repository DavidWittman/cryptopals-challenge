package set_three

import (
	"testing"
)

func TestEncryptRandomString(t *testing.T) {
	_ = EncryptRandomString()
}

func TestPaddingOracle(t *testing.T) {
	for i := 0; i < 1000; i++ {
		ciphertext := EncryptRandomString()
		if !PaddingOracle(ciphertext) {
			t.Errorf("PaddingOracle returned false for ciphertext %v", ciphertext)
		}
	}
}
