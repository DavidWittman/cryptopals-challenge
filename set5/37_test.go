package set_five

import (
	"math/big"
	"testing"
	"time"
)

func TestSRPLoginAEquals0(t *testing.T) {
	addr := "localhost:3335"
	server := &SRPServer{}
	go StartServer(server.Handler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(500 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	if success := client.MaliciousLogin("", big.NewInt(0)); !success {
		t.Errorf("Malicious login failed!")
	}
}

func TestSRPLoginAEqualsN(t *testing.T) {
	addr := "localhost:3336"
	server := &SRPServer{}
	go StartServer(server.Handler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(500 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	n, _, _ := GetNISTParams()

	if success := client.MaliciousLogin("", n); !success {
		t.Errorf("Malicious login failed!")
	}
}

func TestSRPLoginAEquals2N(t *testing.T) {
	addr := "localhost:3337"
	server := &SRPServer{}
	go StartServer(server.Handler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(500 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	n, _, _ := GetNISTParams()

	if success := client.MaliciousLogin("", new(big.Int).Mul(n, big.NewInt(2))); !success {
		t.Errorf("Malicious login failed!")
	}
}

func TestSRPLoginAEquals3N(t *testing.T) {
	addr := "localhost:3338"
	server := &SRPServer{}
	go StartServer(server.Handler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(500 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	n, _, _ := GetNISTParams()

	if success := client.MaliciousLogin("", new(big.Int).Mul(n, big.NewInt(3))); !success {
		t.Errorf("Malicious login failed!")
	}
}
