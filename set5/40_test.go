package set_five

import (
	"bytes"
	"testing"
)

func TestCRTAttack(t *testing.T) {
	secret := []byte("YELLOW SUBMARINE")
	result := CRTAttack(BroadcastRSA(secret))

	if !bytes.Equal(result, secret) {
		t.Errorf("Decryption error. Got: %s", result)
	}
}
