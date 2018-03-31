package set6

import (
	"bytes"
	"testing"
)

func TestOracleSameMessageTwice(t *testing.T) {
	msg := []byte("YELLOW SUBMARINE")
	r := NewRSAOracle()
	cipher := r.Encrypt(msg)

	result, err := r.Decrypt(cipher)
	if err != nil {
		t.Errorf("Error decrypting cipher")
	}
	if !bytes.Equal(result, msg) {
		t.Errorf("Decryption error. Got: %s", result)
	}

	_, err = r.Decrypt(cipher)
	if err == nil {
		t.Errorf("Oracle did not reject duplicate ciphertext")
	}
}

func TestRecoverMessage(t *testing.T) {
	msg := []byte("YELLOW SUBMARINE")
	r := NewRSAOracle()
	cipher := r.Encrypt(msg)
	// Decrypt once to ensure that we can't use the same cipher
	_, _ = r.Decrypt(cipher)

	result := RecoverMessage(cipher, r)
	if !bytes.Equal(result, msg) {
		t.Errorf("Incorrect message from ciphertext. Got: %s", result)
	}
}
