package set_five

import (
	"testing"
	"time"
)

// Simulate a MITM by having Alice connect directly to Eve
// Alice -> Eve (:3666) -> Bob (:3333)
func TestDHMaliciousGEquals1(t *testing.T) {
	bobAddr := "localhost:3333"
	eveAddr := "localhost:3666"

	go EveGEquals1(eveAddr, bobAddr)
	go Bob(bobAddr)

	// Sleep for a bit to allow time for Bob and Eve to start
	time.Sleep(250 * time.Millisecond)

	result, err := Alice(eveAddr)
	if err != nil {
		t.Error(err)
	}

	if result != SECRET_MESSAGE {
		t.Errorf("Alice received incorrect response.\nExpected:\t%v\nGot:\t%v", SECRET_MESSAGE, result)
	}
}

// Simulate a MITM by having Alice connect directly to Eve
// Alice -> Eve (:4666) -> Bob (:4444)
func TestDHMaliciousGEqualsP(t *testing.T) {
	bobAddr := "localhost:4444"
	eveAddr := "localhost:4666"

	go EveGEqualsP(eveAddr, bobAddr)
	go Bob(bobAddr)

	// Sleep for a bit to allow time for Bob and Eve to start
	time.Sleep(250 * time.Millisecond)

	result, err := Alice(eveAddr)
	if err != nil {
		t.Error(err)
	}

	if result != SECRET_MESSAGE {
		t.Errorf("Alice received incorrect response.\nExpected:\t%v\nGot:\t%v", SECRET_MESSAGE, result)
	}
}

// Simulate a MITM by having Alice connect directly to Eve
// Alice -> Eve (:5666) -> Bob (:5555)
func TestDHMaliciousGEqualsPMinus1(t *testing.T) {
	bobAddr := "localhost:5555"
	eveAddr := "localhost:5666"

	go EveGEqualsPMinus1(eveAddr, bobAddr)
	go Bob(bobAddr)

	// Sleep for a bit to allow time for Bob and Eve to start
	time.Sleep(250 * time.Millisecond)

	result, err := Alice(eveAddr)
	if err != nil {
		t.Error(err)
	}

	if result != SECRET_MESSAGE {
		t.Errorf("Alice received incorrect response.\nExpected:\t%v\nGot:\t%v", SECRET_MESSAGE, result)
	}
}
