package set_five

import (
	"math/big"
	"testing"
)

func TestDHSession(t *testing.T) {
	p, g := big.NewInt(37), big.NewInt(5)

	alice := NewDHSession(p, g)
	bob := NewDHSession(p, g)

	alice.GenerateSessionKeys(bob.PublicKey)
	bob.GenerateSessionKeys(alice.PublicKey)

	if alice.sessionKey != bob.sessionKey {
		t.Errorf("Session keys do not match!\n\n%v\n%v", alice, bob)
	}

	t.Logf("Session key: %v", alice.sessionKey)
}

func TestDHSession3000(t *testing.T) {
	p, g := big.NewInt(37), big.NewInt(5)

	for i := 0; i < 3000; i++ {
		alice := NewDHSession(p, g)
		bob := NewDHSession(p, g)

		alice.GenerateSessionKeys(bob.PublicKey)
		bob.GenerateSessionKeys(alice.PublicKey)

		if alice.sessionKey != bob.sessionKey {
			t.Errorf("Session keys do not match!\n\n%v\n%v", alice, bob)
		}
	}
}

func TestDHSessionNIST(t *testing.T) {
	g, p, err := GetNISTParams()
	if err != nil {
		t.Errorf("Error generating NIST params")
	}

	alice := NewDHSession(p, g)
	bob := NewDHSession(p, g)

	alice.GenerateSessionKeys(bob.PublicKey)
	bob.GenerateSessionKeys(alice.PublicKey)

	if alice.sessionKey != bob.sessionKey {
		t.Errorf("Session keys do not match!\n\n%v\n%v", alice, bob)
	}

	t.Logf("Session key: %v", alice.sessionKey)
}
