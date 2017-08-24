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
	"net"
)

// Eve is an evil TCP listener which execute a MITM attack against a
// two parties (Alice and Bob) in a DH key exchange.
//
// `listen` is the ip:port or :port to listen on
// `dest` is the ip:port of Bob
func Eve35(listen, dest string) {
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

	server := &DHClient{"Eve", conn, nil}
	exchange := server.ReadMessage(DHE_MSG_EXCHANGE)
	e := exchange.(DHExchange)

	server.session = NewDHSession(e.Group.P, e.Group.G)
	// Use p for generating Eve's session keys so that we generate the same
	// session key between the two sessions
	server.session.GenerateSessionKeys(e.Group.P)

	// Use P for the public key to make the session key predictable
	e.PublicKey = e.Group.P

	// Send exchange object with fixed key to Alice
	server.Send(e)

	// Establish fixed-key MITM connection to Bob
	clientConn, err := net.Dial("tcp", dest)
	if err != nil {
		panic(err)
	}
	defer clientConn.Close()

	clientSession := NewDHSession(e.Group.P, e.Group.G)
	clientSession.PublicKey = e.Group.P
	client := &DHClient{"EveClient", clientConn, clientSession}
	client.Send(e)

	// We don't actually need Bob's public key because our fixed-key attack has
	// made the session key preditable.
	_ = client.ReadMessage(DHE_MSG_EXCHANGE)
	clientSession.GenerateSessionKeys(e.Group.P)

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
