package set_three

import (
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
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
	paddedResult := BruteForcePaddingOracle(encrypted, CBCPaddingOracle)
	base64Result := string(cryptopals.MaybePKCS7Unpad(paddedResult))
	result, err := cryptopals.ReadBase64String(base64Result)
	if err != nil {
		t.Errorf("Base 64 decoding failed: %s", err)
	}
	t.Logf(result)
}

func TestGenerateInjectionPad(t *testing.T) {
	i2, err := cryptopals.GenerateRandomBytes(16)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	// Test pad creation for all pad lengths
	for i := 1; i < len(i2); i++ {
		result := generateInjectionPad(i2, i)
		correctPad := byte(i + 1)

		// Check the last i bytes of our result to make sure that
		//   i2[len(i2)-j] ^ result[len(result)-j] == correctPad
		for j := 1; j <= i; j++ {
			if pad := (i2[len(i2)-j] ^ result[len(result)-j]); pad != correctPad {
				t.Errorf("Invalid injection pad.\n  c1': %v\n  i2: %v\n  padLength: %d", result, i2, i)
			}
		}
	}
}
