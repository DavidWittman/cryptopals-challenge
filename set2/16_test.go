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

func TestSanitizeInput(t *testing.T) {
	expected := "\";\"admin\"=\"true\";\""
	result := sanitizeInput(";admin=true;")
	if result != expected {
		t.Errorf("Input sanitize failed. Expected: %v, Got: %v", result, expected)
	}
}

func TestDecryptCommentAndCheckAdmin(t *testing.T) {
	encrypted := EncryptedComment("ohai")
	result, err := DecryptCommentAndCheckAdmin(encrypted)
	if err != nil {
		t.Errorf("Error decrypting comment: %s", err)
	}
	if result == true {
		t.Errorf("Incorrectly determined comment as admin")
	}
}

func TestBitflipInjectCBC(t *testing.T) {

}
