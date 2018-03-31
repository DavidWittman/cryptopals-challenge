package set6

import (
	"bytes"
	"testing"
)

const SECRET_41 = "{time: 1356304276, social: '555-55-5555',}"

func TestOracleSameMessageTwice(t *testing.T) {
	msg := []byte(SECRET_41)
	r := NewRSAOracle()
	cipher := r.Encrypt(msg)

	result, err := r.Decrypt(cipher)
	if err != nil {
		t.Errorf("Error decrypting cipher")
	}
	if !bytes.Equal(result, msg) {
		t.Errorf("Decryption error. Got: %s", result)
	}

	if _, err = r.Decrypt(cipher); err == nil {
		t.Errorf("Oracle did not reject duplicate ciphertext")
	}
}

func TestRecoverMessage(t *testing.T) {
	msg := []byte(SECRET_41)
	r := NewRSAOracle()
	cipher := r.Encrypt(msg)
	// Decrypt once to ensure that we can't use the same cipher
	_, _ = r.Decrypt(cipher)

	result := RecoverMessage(cipher, r)
	if !bytes.Equal(result, msg) {
		t.Errorf("Incorrect message from ciphertext. Got: %s", result)
	}
}
