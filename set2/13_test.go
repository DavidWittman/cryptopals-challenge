package set_two

import (
	"strings"
	"testing"
)

func TestStripMetachars(t *testing.T) {
	metachars := "&="
	tt := []string{
		"foo=bar&baz=42",
		"====foo====bar&baz===42",
		"====================",
		"&&&&&&&&&&&&&&",
		"=======&&&&&===&=&=&=",
		"======42&&&&&&bar+++",
	}

	for _, input := range tt {
		if result := stripMetachars(input); strings.ContainsAny(result, metachars) {
			t.Errorf("Meta characters not stripped: %s", result)
		}
	}
}

func TestProfileFor(t *testing.T) {
	expected := "email=foo@bar.com&uid=10&role=user"
	result := ProfileFor("foo@bar.com")
	if result != expected {
		t.Errorf("Profile incorrect: %s", result)
	}
	result = ProfileFor("fo=o@bar.c&om&")
	if result != expected {
		t.Errorf("Profile incorrect: %s", result)
	}
}

func TestEncryptDecryptUser(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	user1 := NewUser("foo@example.com")
	encrypted := user1.Encrypt(key)
	user2 := DecryptNewUser(encrypted, key)

	if user1.Uid != user2.Uid {
		t.Errorf("Decrypted UID does not match: %s", user2.Uid)
	}

	if user1.Email != user2.Email {
		t.Errorf("Decrypted email does not match: %s", user2.Email)
	}

	if user1.Role != user2.Role {
		t.Errorf("Decrypted role does not match: %s", user2.Role)
	}
}

func TestProfileOracle(t *testing.T) {
	cipher := ProfileOracle("foo@example.com")
	if len(cipher) == 0 {
		t.Errorf("Ciphertext length is 0")
	}
}
