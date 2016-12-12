package set_three

import (
	"testing"
)

func TestDecryptCTRMessage(t *testing.T) {
	decrypted := DecryptCTRMessage()
	t.Log(string(decrypted))
}
