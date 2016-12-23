package set_three

import (
	"bytes"
	"testing"
)

func TestMTEncryptDecrypt(t *testing.T) {
	key := uint32(42)
	plaintext := []byte("Wax a chump like a candle")

	mt := NewMersenneTwister()
	mt.Seed(key)

	encrypted := make([]byte, len(plaintext))
	mt.CryptBlocks(encrypted, plaintext)

	mt.Seed(key)
	decrypted := make([]byte, len(encrypted))
	mt.CryptBlocks(decrypted, encrypted)

	if bytes.Compare(decrypted, plaintext) != 0 {
		t.Errorf("Decrypted bytes do not match plaintext: %s", decrypted)
	}
}
