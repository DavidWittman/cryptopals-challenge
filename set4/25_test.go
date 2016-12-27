package set_four

import (
	"crypto/aes"
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func TestEncryptFileCTR(t *testing.T) {
	cipher, err := encryptFileCTR("./data/25_plain.txt", cryptopals.RANDOM_KEY, 0)
	if err != nil {
		t.Errorf("Error encrypting file: %s", err)
	}
	if len(cipher) != 2883 {
		t.Errorf("Ciphertext length incorrect: Got: %d, Expected: 2883", len(cipher))
	}
}

func TestEdit(t *testing.T) {
	cipher, err := encryptFileCTR("./data/25_plain.txt", cryptopals.RANDOM_KEY, 0)
	if err != nil {
		t.Errorf("Error encrypting file: %s", err)
	}
	result := Edit(cipher, cryptopals.RANDOM_KEY, 17, []byte("Mom's Spaghetti,"))

	block, err := aes.NewCipher(cryptopals.RANDOM_KEY)
	if err != nil {
		t.Errorf("Error creating AES cipher")
	}

	blockMode := cryptopals.NewCTR(block, 0)
	decrypted := make([]byte, len(result))
	blockMode.CryptBlocks(decrypted, result)
	t.Log(string(decrypted))
}
