/*
 * Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
 * Use the code you just worked out to build a protocol and an "echo" bot. You
 * don't actually have to do the network part of this if you don't want; just
 * simulate that. The protocol is:
 *
 *     A->B
 *     Send "p", "g", "A"
 *     B->A
 *     Send "B"
 *     A->B
 *     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 *     B->A
 *     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 *
 * (In other words, derive an AES key from DH with SHA1, use it in both
 * directions, and do CBC with random IVs appended or prepended to the message).
 *
 * Now implement the following MITM attack:
 *
 *     A->M
 *     Send "p", "g", "A"
 *     M->B
 *     Send "p", "g", "p"
 *     B->M
 *     Send "B"
 *     M->A
 *     Send "p"
 *     A->M
 *     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 *     M->B
 *     Relay that to B
 *     B->M
 *     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 *     M->A
 *     Relay that to A
 *
 * M should be able to decrypt the messages. "A" and "B" in the protocol --- the
 * public keys, over the wire --- have been swapped out with "p". Do the DH math
 * on this quickly to see what that does to the predictability of the key.
 *
 * Decrypt the messages from M's vantage point as they go by.
 *
 * Note that you don't actually have to inject bogus parameters to make this
 * attack work; you could just generate Ma, MA, Mb, and MB as valid DH
 * parameters to do a generic MITM attack. But do the parameter injection
 * attack; it's going to come up again.
 *
 */

/* NOTES:
 *  - This fixed-key attack works by setting the public keys for the session
 *    to the same value as `p`. This makes the session key calculated as
 *    follows:
 *
 *        s = (p ^ k) % p
 *
 *    And p ^ k always produces a multiple of p (with the exception of when the
 *    private key is 0, because p^0 == 1), meaning the session key can be
 *    easily predicted.
 */

package set_five

import (
	"log"
	"net"
)

const (
	SECRET_MESSAGE = "Go Ninja, Go Ninja, GO: Go Ninja, Go Ninja, GO!"
)

// Bob listens on a TCP socket and acts as the server party in a Diffie
// Hellman Key Exchange
//
// `listen` is the ip:port or :port to listen on
func Bob(listen string) {
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

	server := &DHClient{"Bob", conn, nil}
	e := server.ReadDHE()

	// Server = Bob, Client = Alice
	server.session = NewDHSession(e.Group.P, e.Group.G)
	server.session.GenerateSessionKeys(e.PublicKey)

	// Send over our public key in an exchange object so Alice can generate s
	e.PublicKey = server.session.PublicKey
	server.Send(e)

	// Now we're expecting Alice to send an encrypted message
	message, err := server.ReadEncrypted()
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
// `listen` is the ip:port or :port to listen on
// `dest` is the ip:port of Bob
func Eve(listen, dest string) {
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
	e := server.ReadDHE()

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
	_ = client.ReadDHE()
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

// Alice is the client party in a Diffie-Hellman Key Exchange
// `connect` is the address of the server to connect to
func Alice(connect string) (string, error) {
	p, g, err := GetNISTParams()
	if err != nil {
		return "", err
	}
	sess := NewDHSession(p, g)
	exchange := DHExchange{sess.Group, sess.PublicKey}

	conn, err := net.Dial("tcp", connect)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	client := &DHClient{"Alice", conn, sess}
	client.Send(exchange)

	bob := client.ReadDHE()

	sess.GenerateSessionKeys(bob.PublicKey)

	// Now that we have the session key, send the secret message to Bob
	err = client.SendEncrypted([]byte(SECRET_MESSAGE))
	if err != nil {
		return "", err
	}

	message, err := client.ReadEncrypted()
	if err != nil {
		return "", err
	}

	return string(message), nil
}
