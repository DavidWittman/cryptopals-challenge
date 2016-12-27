package set_three

import (
	"bytes"
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func TestDecryptCTRMessage(t *testing.T) {
	decrypted := DecryptCTRMessage()
	t.Log(string(decrypted))
}

func TestEncryptDecryptCTR(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("aosdjajsfjsa09jf awjeoifj30afj0wfwae\x030\x00")

	// Encrypt
	encrypted, err := cryptopals.AESCTR(plaintext, key, 0)
	if err != nil {
		t.Errorf("Error encrypting with CTR: %s", err)
	}

	// Decrypt
	decrypted, err := cryptopals.AESCTR(encrypted, key, 0)
	if err != nil {
		t.Errorf("Error decrypting with CTR: %s", err)
	}

	if bytes.Compare(decrypted, plaintext) != 0 {
		t.Errorf("Decrypted bytes do not match plaintext. %v", decrypted)
	}
}
