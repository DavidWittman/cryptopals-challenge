package set_four

import (
	"bytes"
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func TestValidASCII(t *testing.T) {
	for _, tt := range []struct {
		input    []byte
		expected bool
	}{
		{[]byte("zomg"), true},
		{[]byte{}, true},
		{[]byte{0, 0, 0, 0}, true},
		{[]byte{0, 1, 2, 3}, true},
		{[]byte{127, 0x41, 0x65}, true},
		{[]byte{0x41, 128}, false},
		{[]byte{255}, false},
		{[]byte{0x45, 0x46, 0x47, 132, 0x48, 0x49}, false},
	} {
		if result := validASCII(tt.input); result != tt.expected {
			t.Errorf("ASCII validation failed (expected %v) for %v", tt.expected, tt.input)
		}
	}
}

func TestValidateAndEncrypt(t *testing.T) {
	input := []byte("this is just a message to encrypt that is more than three blocks long")
	result, err := ValidateAndEncrypt(input)
	if err != nil {
		t.Errorf("Error validating and encrypting: %v", err)
	}
	// This should Never Happen
	if bytes.Compare(result, input) == 0 {
		t.Errorf("Why is the encrypted result the same as the plaintext?")
	}
}

func TestValidateAndEncryptErrorType(t *testing.T) {
	input := []byte{0x41, 0x41, 129, 0x42, 0x43}
	result, err := ValidateAndEncrypt(input)
	if _, ok := err.(InvalidASCIIError); !ok {
		t.Errorf("Invalid error type returned: %v", err)
	}
	if bytes.Compare(result, input) != 0 {
		t.Errorf("Plaintext value not returned correctly: %v", result)
	}
}

func TestDecryptAndValidate(t *testing.T) {
	input := []byte("this is just a message to encrypt that is more than three blocks long")
	encrypted, err := cryptopals.EncryptAESCBC(input, cryptopals.RANDOM_KEY, cryptopals.RANDOM_KEY)
	if err != nil {
		t.Errorf("Error encrypting input for test. Likely unrelated.")
	}
	result, err := DecryptAndValidate(encrypted)
	if err != nil {
		t.Errorf("Error decrypting and validating: %v", err)
	}
	if bytes.Compare(cryptopals.MaybePKCS7Unpad(result), input) != 0 {
		t.Errorf("Decryption failed.\nExpected:\t%v\nGot:\t\t%v", input, result)
	}
}

func TestDecryptAndValidateErrorType(t *testing.T) {
	input := []byte{0x41, 0x41, 129, 0x42, 0x43}
	encrypted, err := cryptopals.EncryptAESCBC(input, cryptopals.RANDOM_KEY, cryptopals.RANDOM_KEY)
	if err != nil {
		t.Errorf("Error encrypting input for test. Likely unrelated.")
	}
	result, err := DecryptAndValidate(encrypted)
	if _, ok := err.(InvalidASCIIError); !ok {
		t.Errorf("Invalid error type returned: %v", err)
	}
	if bytes.Compare(cryptopals.MaybePKCS7Unpad(result), input) != 0 {
		t.Errorf("Decryption failed.\nExpected:\t%v\nGot:\t\t%v", input, result)
	}
}

func TestChallenge27(t *testing.T) {
	result, err := Challenge27()
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if bytes.Compare(result, cryptopals.RANDOM_KEY) != 0 {
		t.Errorf("Extracted key does not match.\nExpected:\t%v\nGot:\t\t%v", cryptopals.RANDOM_KEY, result)
	}
}
