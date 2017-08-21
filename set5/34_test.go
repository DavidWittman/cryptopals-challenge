package set_five

import (
	"testing"
	"time"
)

func TestDHExchange(t *testing.T) {
	listen := "localhost:3000"
	go Bob(listen)
	_ = Alice(listen)
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

	if err := Alice(eveAddr); err != nil {
		t.Error(err)
	}
}
