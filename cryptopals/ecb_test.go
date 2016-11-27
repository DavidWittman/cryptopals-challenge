package cryptopals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestEcbEncryptDecrypt(t *testing.T) {
	key := "YELLOW SUBMARINE"
	text := []byte("✓ this is a test string to encrypt and decrypt")

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	encrypt := NewECBEncrypter(block)
	encrypted := make([]byte, len(text))
	encrypt.CryptBlocks(encrypted, text)

	decrypt := NewECBDecrypter(block)
	decrypted := make([]byte, len(encrypted))
	decrypt.CryptBlocks(decrypted, encrypted)

	if bytes.Compare(text, decrypted) != 0 {
		t.Errorf("Decrypted string does not match.\n - Expected: %s\n - Got: %s", text, decrypted)
	}
}
