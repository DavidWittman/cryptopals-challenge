package set_five

import (
	"testing"
	"time"
)

func TestDHExchange(t *testing.T) {
	listen := "localhost:3000"
	go Bob(listen)

	// Sleep for a bit to allow time for Bob to start
	time.Sleep(250 * time.Millisecond)

	result, err := Alice(listen)
	if err != nil {
		t.Error(err)
	}
	if result != SECRET_MESSAGE {
		t.Errorf("Encrypted response does not match.\n\tExpected:\t%v\n\tGot:\t%v", SECRET_MESSAGE, result)
	}
}

// Simulate a MITM by having Alice connect directly to Eve
// Alice -> Eve (:3666) -> Bob (:3000)
func TestDHFixedKeyAttack(t *testing.T) {
	bobAddr := "localhost:3333"
	eveAddr := "localhost:3666"

	go Eve(eveAddr, bobAddr)
	go Bob(bobAddr)

	// Sleep for a bit to allow time for Bob and Eve to start
	time.Sleep(250 * time.Millisecond)

	result, err := Alice(eveAddr)
	if err != nil {
		t.Error(err)
	}
	if result != SECRET_MESSAGE {
		t.Errorf("Encrypted response does not match.\n\tExpected:\t%v\n\tGot:\t%v", SECRET_MESSAGE, result)
	}
}
