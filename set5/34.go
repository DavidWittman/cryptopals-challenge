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

// TODO(dw): Move `encode` to `Send`
package set_five

import (
	"bytes"
	"encoding/gob"
	"log"
	"math/big"
	"net"
)

const (
	SECRET_MESSAGE = "Go Ninja, Go Ninja, GO: Go Ninja, Go Ninja, GO!"
)

// StartServer creates a TCP listener for a Diffie Hellman Exchange
//
// `listen` is the ip:port or :port to listen on
func StartServer(listen string) {
	socket, err := net.Listen("tcp", listen)
	if err != nil {
		panic(err)
	}
	defer socket.Close()

	for {
		conn, err := socket.Accept()
		if err != nil {
			log.Println("Error establishing connection:", err)
			continue
		}

		server := &DHClient{"Bob", conn, nil}
		exchange := server.ReadMessage(DHE_MSG_EXCHANGE)
		e := exchange.(DHExchange)

		// Server = Bob, Client = Alice
		server.session = NewDHSession(e.Group.P, e.Group.G)
		server.session.GenerateSessionKeys(e.PublicKey)

		// Send over our public key in an exchange object so Alice can generate s
		e.PublicKey = server.session.PublicKey
		b, err := encode(e)
		if err != nil {
			panic(err)
		}
		server.Send(b)

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
}

func encode(data interface{}) ([]byte, error) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)
	if err := encoder.Encode(data); err != nil {
		return []byte{}, err
	}
	return b.Bytes(), nil
}

func Client(connect string) error {
	p, g := big.NewInt(37), big.NewInt(5)
	alice := NewDHSession(p, g)
	exchange := DHExchange{alice.Group, alice.PublicKey}

	b, err := encode(exchange)
	if err != nil {
		return err
	}

	conn, err := net.Dial("tcp", connect)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := &DHClient{"Alice", conn, alice}
	client.Send(b)

	server := client.ReadMessage(DHE_MSG_EXCHANGE)
	bob := server.(DHExchange)

	alice.GenerateSessionKeys(bob.PublicKey)

	// Now that we have the session key, send the secret message to Bob
	err = client.SendEncrypted([]byte(SECRET_MESSAGE))
	if err != nil {
		return err
	}

	_, err = client.ReadEncrypted()
	if err != nil {
		return err
	}

	return nil
}
