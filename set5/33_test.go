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
	g := big.NewInt(2)
	p, ok := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	if !ok {
		t.Errorf("Error setting p")
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
