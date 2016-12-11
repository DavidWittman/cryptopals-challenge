package set_three

import (
	"testing"
)

func TestEncryptRandomString(t *testing.T) {
	_ = EncryptRandomString()
}

func TestCBCPaddingOracle(t *testing.T) {
	for i := 0; i < 1000; i++ {
		ciphertext := EncryptRandomString()
		if !CBCPaddingOracle(ciphertext) {
			t.Errorf("CBCPaddingOracle returned false for ciphertext %v", ciphertext)
		}
	}
}

func TestBruteForcePaddingOracle(t *testing.T) {
	encrypted := EncryptRandomString()
	t.Logf("%v", BruteForcePaddingOracle(encrypted, CBCPaddingOracle))
	t.Logf("%s", BruteForcePaddingOracle(encrypted, CBCPaddingOracle))
}
