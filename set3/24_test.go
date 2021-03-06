package set_three

import (
	"bytes"
	"testing"
	"time"
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

func TestBruteForceMersenneKey(t *testing.T) {
	plaintext := []byte("AAAAAAAAAAAAAA")
	cipher := mtOracle(plaintext)

	result, err := BruteForceMersenneKey(cipher, plaintext)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	t.Logf("Found key: %d", result)
}

func TestCheckToken(t *testing.T) {
	now := uint32(time.Now().Unix())
	token := PasswordTokenOracle(now)
	oldToken := PasswordTokenOracle(now - 61)

	if !CheckToken(token, 60) {
		t.Errorf("Token validation failed")
	}
	if CheckToken(oldToken, 60) {
		t.Errorf("Old token incorrectly identified as valid")
	}
}
