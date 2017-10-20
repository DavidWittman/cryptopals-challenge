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

	time.Sleep(2 * time.Second)
	_ = client.MaliciousLogin("", big.NewInt(0))
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

	time.Sleep(2 * time.Second)

	n, _, _ := GetNISTParams()

	_ = client.MaliciousLogin("", n)
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

	time.Sleep(2 * time.Second)

	n, _, _ := GetNISTParams()

	_ = client.MaliciousLogin("", new(big.Int).Mul(n, big.NewInt(2)))
}

func TestSRPLoginAEquals3N(t *testing.T) {
	addr := "localhost:3337"
	server := &SRPServer{}
	go StartServer(server.Handler, addr)
	// Sleep for a bit to allow time for server to start
	time.Sleep(500 * time.Millisecond)

	client, err := NewSRPClient(addr)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(2 * time.Second)

	n, _, _ := GetNISTParams()

	_ = client.MaliciousLogin("", new(big.Int).Mul(n, big.NewInt(3)))
}
