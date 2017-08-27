/*
 * Implement DH with negotiated groups, and break with malicious "g" parameters
 *
 *     A->B
 *     Send "p", "g"
 *     B->A
 *     Send ACK
 *     A->B
 *     Send "A"
 *     B->A
 *     Send "B"
 *     A->B
 *     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 *     B->A
 *     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 *
 * Do the MITM attack again, but play with "g". What happens with:
 *
 *     g = 1
 *     g = p
 *     g = p - 1
 *
 * Write attacks for each.
 *
 * When does this ever happen?
 *
 * Honestly, not that often in real-world systems. If you can mess with "g",
 * chances are you can mess with something worse. Most systems pre-agree on a
 * static DH group. But the same construction exists in Elliptic Curve
 * Diffie-Hellman, and this becomes more relevant there.
 */

package set_five

import (
	"log"
	"math/big"
	"net"
)

// Eve is an evil TCP listener which execute a MITM attack against a
// two parties (Alice and Bob) in a DH key exchange.
//
// This version sets g equal to 1, which results in B and s being equal to 1:
//
//     B = g**b % p = 1**b % p = 1
//     s = B**a % p = 1**a % p = 1
//
// `listen` is the ip:port or :port to listen on
// `dest` is the ip:port of Bob
func EveGEquals1(listen, dest string) {
	// When g == 1, B == 1 && s == 1
	g := big.NewInt(1)
	socket, err := net.Listen("tcp", listen)
	if err != nil {
		panic(err)
	}
	defer socket.Close()

	conn, err := socket.Accept()
	if err != nil {
		log.Println("Error establishing connection:", err)
		panic(err)
	}

	server := NewDHClient("Eve", conn, nil)
	e := server.ReadDHE()

	// Manipulate g, and use g as A's public key to generate a session key of 1
	server.session = NewDHSession(e.Group.P, g)
	server.session.GenerateSessionKeys(g)

	// Update the exchange object to use Eve's public key
	e.PublicKey = server.session.PublicKey
	server.Send(e)

	// Establish fixed-key MITM connection to Bob
	clientConn, err := net.Dial("tcp", dest)
	if err != nil {
		panic(err)
	}
	defer clientConn.Close()

	clientSession := NewDHSession(e.Group.P, g)
	client := NewDHClient("EveClient", clientConn, clientSession)
	client.Send(e)

	_ = client.ReadDHE()
	// Use g as the Public Key to generate a session key of 1
	clientSession.GenerateSessionKeys(g)

	// Intercept two messages: A -> E -> B, B -> E -> A
	message, err := server.ReadEncrypted()
	if err != nil {
		panic(err)
	}

	err = client.SendEncrypted(message)
	if err != nil {
		panic(err)
	}

	message, err = client.ReadEncrypted()
	if err != nil {
		panic(err)
	}

	err = server.SendEncrypted(message)
	if err != nil {
		panic(err)
	}
}

// Eve is an evil TCP listener which execute a MITM attack against a
// two parties (Alice and Bob) in a DH key exchange.
//
// This version sets g equal to p, which results in B and s being equal to 0:
//
//     B = p^b % p = 0
//     s = (B ^ a) % p = (0 ^ a) % p = 0
//
// `listen` is the ip:port or :port to listen on
// `dest` is the ip:port of Bob
func EveGEqualsP(listen, dest string) {
	// When g == p, B == 0 && s == 0
	socket, err := net.Listen("tcp", listen)
	if err != nil {
		panic(err)
	}
	defer socket.Close()

	conn, err := socket.Accept()
	if err != nil {
		log.Println("Error establishing connection:", err)
		panic(err)
	}

	server := NewDHClient("Eve", conn, nil)
	e := server.ReadDHE()

	// Manipulate g to be p, and use 0 as A's public key to generate a session key of 0
	server.session = NewDHSession(e.Group.P, e.Group.P)
	server.session.GenerateSessionKeys(big.NewInt(0))

	// Update the exchange object to use Eve's public key
	e.PublicKey = server.session.PublicKey
	server.Send(e)

	// Establish fixed-key MITM connection to Bob
	clientConn, err := net.Dial("tcp", dest)
	if err != nil {
		panic(err)
	}
	defer clientConn.Close()

	clientSession := NewDHSession(e.Group.P, e.Group.P)
	client := NewDHClient("EveClient", clientConn, clientSession)
	client.Send(e)

	_ = client.ReadDHE()
	// Use 0 as the Public Key to generate a session key of 0
	clientSession.GenerateSessionKeys(big.NewInt(0))

	// Intercept two messages: A -> E -> B, B -> E -> A
	message, err := server.ReadEncrypted()
	if err != nil {
		panic(err)
	}

	err = client.SendEncrypted(message)
	if err != nil {
		panic(err)
	}

	message, err = client.ReadEncrypted()
	if err != nil {
		panic(err)
	}

	err = server.SendEncrypted(message)
	if err != nil {
		panic(err)
	}
}

// Eve is an evil TCP listener which execute a MITM attack against a
// two parties (Alice and Bob) in a DH key exchange.
//
// This version sets g equal to p-1, which results in B and s being equal to 1:
//
//     B = (p-1)^b % p = 1
//     s = (B ^ a) % p = (1 ^ a) % p = 1
//
// `listen` is the ip:port or :port to listen on
// `dest` is the ip:port of Bob
func EveGEqualsPMinus1(listen, dest string) {
	// When g == p-1, B == 1 && s == 1
	socket, err := net.Listen("tcp", listen)
	if err != nil {
		panic(err)
	}
	defer socket.Close()

	conn, err := socket.Accept()
	if err != nil {
		log.Println("Error establishing connection:", err)
		panic(err)
	}

	server := NewDHClient("Eve", conn, nil)
	e := server.ReadDHE()

	// g = p - 1
	g := new(big.Int).Sub(e.Group.P, big.NewInt(1))

	// Manipulate g to be p-1, and use 1 as A's public key to generate a session key of 1
	server.session = NewDHSession(e.Group.P, g)
	server.session.GenerateSessionKeys(big.NewInt(1))

	// Update the exchange object to use Eve's public key
	e.PublicKey = server.session.PublicKey
	server.Send(e)

	// Establish fixed-key MITM connection to Bob
	clientConn, err := net.Dial("tcp", dest)
	if err != nil {
		panic(err)
	}
	defer clientConn.Close()

	clientSession := NewDHSession(e.Group.P, g)
	client := NewDHClient("EveClient", clientConn, clientSession)
	client.Send(e)

	_ = client.ReadDHE()
	// Use 0 as the Public Key to generate a session key of 0
	clientSession.GenerateSessionKeys(big.NewInt(1))

	// Intercept two messages: A -> E -> B, B -> E -> A
	message, err := server.ReadEncrypted()
	if err != nil {
		panic(err)
	}

	err = client.SendEncrypted(message)
	if err != nil {
		panic(err)
	}

	message, err = client.ReadEncrypted()
	if err != nil {
		panic(err)
	}

	err = server.SendEncrypted(message)
	if err != nil {
		panic(err)
	}
}
