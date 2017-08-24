package set_five

import (
	"testing"
	"time"
)

// Simulate a MITM by having Alice connect directly to Eve
// Alice -> Eve (:3666) -> Bob (:3000)
func TestDHMaliciousG1(t *testing.T) {
	bobAddr := "localhost:3333"
	eveAddr := "localhost:3666"

	go Eve35(eveAddr, bobAddr)
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
