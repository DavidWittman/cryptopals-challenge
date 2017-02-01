package set_four

import (
	"bytes"
	"crypto/aes"
	"math/rand"
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func TestEncryptFileCTR(t *testing.T) {
	cipher, err := encryptFileCTR("./testdata/25_plain.txt", cryptopals.RANDOM_KEY, 0)
	if err != nil {
		t.Errorf("Error encrypting file: %s", err)
	}
	if len(cipher) != 2883 {
		t.Errorf("Ciphertext length incorrect: Got: %d, Expected: 2883", len(cipher))
	}
}

func TestEdit(t *testing.T) {
	// Run this test 100 times
	iterations := 100
	// This is the string we're injecting
	spaghetti := []byte("Mom's Spaghetti,")

	cipher, err := encryptFileCTR("./testdata/25_plain.txt", cryptopals.RANDOM_KEY, 0)
	if err != nil {
		t.Errorf("Error encrypting file: %s", err)
	}

	for i := 0; i < iterations; i++ {
		// Generate a random offset
		offset := rand.Intn(len(cipher))
		result := Edit(cipher, cryptopals.RANDOM_KEY, offset, spaghetti)

		block, err := aes.NewCipher(cryptopals.RANDOM_KEY)
		if err != nil {
			t.Errorf("Error creating AES cipher")
		}

		blockMode := cryptopals.NewCTR(block, 0)
		decrypted := make([]byte, len(result))
		blockMode.CryptBlocks(decrypted, result)

		editedBytes := decrypted[offset : offset+len(spaghetti)]
		if bytes.Compare(editedBytes, spaghetti) != 0 {
			t.Errorf("Edit failed.\nExpected:\t%s\nGot:\t\t%s", spaghetti, editedBytes)
		}
	}
}

func TestRecoverPlaintext(t *testing.T) {
	cipher, err := encryptFileCTR("./testdata/25_plain.txt", cryptopals.RANDOM_KEY, 0)
	if err != nil {
		t.Errorf("Error encrypting file: %s", err)
	}
	plaintext := RecoverPlaintext(cipher)
	if bytes.Compare([]byte("I'm back and I'm ringin' the bell"), plaintext[:33]) != 0 {
		t.Errorf("Decrypted plaintext does not match:\n%s", plaintext)
	}
}
