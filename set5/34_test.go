package set_five

import (
	"testing"
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

	// TODO(dw): This fails some of the time when the Client starts up
	// before the servers come online
	if err := Alice(eveAddr); err != nil {
		t.Error(err)
	}
}
