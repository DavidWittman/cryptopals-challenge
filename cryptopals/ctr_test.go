package cryptopals

import (
	"crypto/aes"
	"testing"
)

func TestCBCEncrypt(t *testing.T) {
	plaintext := []byte("this is a sentence which doesn't fit perfectly into a block")

	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("Failed creating AES block: %s", err)
	}

	blockMode := NewCTR(block, 0)
	encrypted := make([]byte, len(plaintext))
	blockMode.CryptBlocks(encrypted, plaintext)
}
