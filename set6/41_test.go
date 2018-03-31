package set6

import (
	"bytes"
	"testing"
)

func TestOracleSameMessageTwice(t *testing.T) {
	msg := []byte("YELLOW SUBMARINE")
	o := NewRSAOracle()
	cipher := o.Encrypt(msg)

	result, err := o.Decrypt(cipher)
	if err != nil {
		t.Errorf("Error decrypting cipher")
	}
	if !bytes.Equal(result, msg) {
		t.Errorf("Decryption error. Got: %s", result)
	}

	_, err = o.Decrypt(cipher)
	if err == nil {
		t.Errorf("Oracle did not reject duplicate ciphertext")
	}
}
