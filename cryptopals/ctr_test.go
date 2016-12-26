package cryptopals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestCTREncrypt(t *testing.T) {
	plaintext := []byte("this is a sentence which doesn't fit perfectly into a block")

	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("Failed creating AES block: %s", err)
	}

	blockMode := NewCTR(block, 0)
	encrypted := make([]byte, len(plaintext))
	blockMode.CryptBlocks(encrypted, plaintext)
}

func TestCTRKeystreamRange(t *testing.T) {
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("Failed creating AES block: %s", err)
	}

	blockMode := NewCTR(block, 0)

	expected := []byte{118, 209, 203, 75, 175, 162, 70, 226, 227, 175, 3, 93, 108, 19, 195, 114}
	keystream := blockMode.KeystreamRange(0, 16)

	if len(keystream) != 16 {
		t.Errorf("Keystream length incorrect: %d", len(keystream))
	}

	if bytes.Compare(keystream, expected) != 0 {
		t.Errorf("Invalid keystream. Expected: %v, Got: %v", expected, keystream)
	}

	if blockMode.counter != 0 {
		t.Errorf("Counter was not reset after generating keystream")
	}
}

func TestCTRPartialKeystreamRange(t *testing.T) {
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("Failed creating AES block: %s", err)
	}

	blockMode := NewCTR(block, 0)

	expected := []byte{175, 3, 93, 108, 19, 195, 114, 210, 236, 108, 220, 152, 109, 18, 222, 207, 218}
	keystream := blockMode.KeystreamRange(9, 17)

	if len(keystream) != 17 {
		t.Errorf("Keystream length incorrect: %d", len(keystream))
	}

	if bytes.Compare(keystream, expected) != 0 {
		t.Errorf("Invalid keystream.\nExpected:\t%v\nGot:\t\t%v", expected, keystream)
	}
}

func TestCTRKeystreamRangeSingleByte(t *testing.T) {
	block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("Failed creating AES block: %s", err)
	}

	blockMode := NewCTR(block, 0)

	expected := []byte{236}
	keystream := blockMode.KeystreamRange(17, 1)

	if len(keystream) != 1 {
		t.Errorf("Keystream length incorrect: %d", len(keystream))
	}

	if bytes.Compare(keystream, expected) != 0 {
		t.Errorf("Invalid keystream.\nExpected:\t%v\nGot:\t\t%v", expected, keystream)
	}
}
