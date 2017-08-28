package set_five

import (
	"testing"
	"time"
)

func TestSRP(t *testing.T) {
	addr := "localhost:3333"
	server := &SRPServer{}
	go StartServer(server.Handler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(250 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(500 * time.Millisecond)
	if success := client.Login(PASSWORD); !success {
		t.Errorf("Error logging in with password: %s", PASSWORD)
	}
}

func TestSRPWrongPassword(t *testing.T) {
	addr := "localhost:3334"
	server := &SRPServer{}
	go StartServer(server.Handler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(250 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(500 * time.Millisecond)
	if success := client.Login("wrongpassword"); success {
		t.Errorf("Logged in with incorrect password!")
	}
}
