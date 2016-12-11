package cryptopals

import (
	"bytes"
	"testing"
)

func TestAESCBCEncryptDecrypt(t *testing.T) {
	input := []byte("this is some plaintext")
	key := RANDOM_KEY
	iv := []byte("YELLOW SUBMARINE")

	encrypted, _ := EncryptAESCBC(input, key, iv)
	decrypted, _ := DecryptAESCBC(encrypted, key, iv)

	if bytes.Compare(MaybePKCS7Unpad(decrypted), input) != 0 {
		t.Errorf("Encryption/decryption mismatch:\n%s\n%s", decrypted, input)
	}
}

func TestAESECBEncryptDecrypt(t *testing.T) {
	input := []byte("this is some plaintext")
	key := RANDOM_KEY

	encrypted, _ := EncryptAESECB(input, key)
	decrypted, _ := DecryptAESECB(encrypted, key)

	if bytes.Compare(decrypted, input) != 0 {
		t.Errorf("Encryption/decryption mismatch: %s", decrypted)
	}
}
