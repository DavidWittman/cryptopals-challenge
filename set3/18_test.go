package set_three

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func TestDecryptCTRMessage(t *testing.T) {
	decrypted := DecryptCTRMessage()
	t.Log(string(decrypted))
}

func TestEncryptDecryptCTR(t *testing.T) {
	key := "YELLOW SUBMARINE"
	plaintext := []byte("aosdjajsfjsa09jf awjeoifj30afj0wfwae\x030\x00")

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		t.Errorf("Error generating AES cipher: %s", err)
	}

	// Encrypt
	blockMode := cryptopals.NewCTR(block, 0)
	encrypted := make([]byte, len(plaintext))
	blockMode.CryptBlocks(encrypted, plaintext)

	// Decrypt
	blockMode = cryptopals.NewCTR(block, 0)
	decrypted := make([]byte, len(encrypted))
	blockMode.CryptBlocks(decrypted, encrypted)

	if bytes.Compare(decrypted, plaintext) != 0 {
		t.Errorf("Decrypted bytes do not match plaintext. %v", decrypted)
	}
}
