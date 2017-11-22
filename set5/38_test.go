package set_five

import (
	"testing"
	"time"
)

func TestSimpleSRP(t *testing.T) {
	addr := "localhost:3339"
	server := &SRPServer{}
	go StartServer(server.SimpleHandler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(500 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	if success := client.SimpleLogin(PASSWORD); !success {
		t.Errorf("Error logging in with password: %s", PASSWORD)
	}
}

func TestSimpleSRPWrongPassword(t *testing.T) {
	addr := "localhost:3340"
	server := &SRPServer{}
	go StartServer(server.SimpleHandler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(500 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	if success := client.SimpleLogin("wrongpassword"); success {
		t.Errorf("Logged in with incorrect password!")
	}
}

func TestSimpleSRPMITM(t *testing.T) {
	addr := "localhost:3341"
	server := &SRPServer{}

	// Run the client in a goroutine because we need to wait for the server
	go func() {
		// Sleep for a bit to allow time for server to start
		time.Sleep(500 * time.Millisecond)

		client, err := NewSRPClient(addr)
		if err != nil {
			t.Error(err)
		}

		if success := client.SimpleLogin(PASSWORD); !success {
			t.Errorf("Error logging in with password: %s", PASSWORD)
		}
	}()

	StartServer(server.SimpleHandlerMITM, addr)
}
