package set_two

import (
	"testing"
)

func TestEncryptedComment(t *testing.T) {
	expectedLen := 80
	result := EncryptedComment("wtf")
	if len(result) != expectedLen {
		t.Errorf("Error encrypting comment \"wtf\": Unexpected output length %d. Expected %d",
			len(result), expectedLen)
	}
}
