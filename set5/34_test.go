package set_five

import (
	"testing"
)

func TestDHExchange(t *testing.T) {
	listen := "localhost:3000"
	go StartServer(listen)
	_ = Client(listen)
}

// Simulate a MITM by having Alice connect directly to Eve
// Alice -> Eve (:3666) -> Bob (:3000)
func TestDHMITM(t *testing.T) {
	bobAddr := "localhost:3000"
	eveAddr := "localhost:3666"

	go StartMITMServer(eveAddr, bobAddr)
	go StartServer(bobAddr)

	if err := Client(eveAddr); err != nil {
		t.Error(err)
	}
}
