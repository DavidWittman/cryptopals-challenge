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

package set_five

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
	"net"
)

type DHExchange struct {
	Group     *DHGroup
	PublicKey *big.Int
}

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
			fmt.Println("Error establishing connection:", err)
			continue
		}

		var exchange DHExchange
		msgReader := bytes.NewReader(read(conn))
		decoder := gob.NewDecoder(msgReader)

		err = decoder.Decode(&exchange)
		if err != nil {
			panic(err)
		}

		client := NewDHClient(exchange.Group.P, exchange.Group.G)
		client.GenerateSessionKey(exchange.PublicKey)
		fmt.Println("Session key:", sha1.Sum(client.sessionKey[:]))

		exchange.PublicKey = client.PublicKey
		b, err := encode(exchange)
		if err != nil {
			panic(err)
		}
		send(conn, b)
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

func read(conn net.Conn) []byte {
	var length uint16

	err := binary.Read(conn, binary.LittleEndian, &length)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, length)
	_, err = io.ReadFull(conn, msg)
	if err != nil {
		panic(err)
	}

	return msg
}

func Client(connect string) error {
	p, g := big.NewInt(37), big.NewInt(5)
	client := NewDHClient(p, g)
	exchange := DHExchange{client.Group, client.PublicKey}

	b, err := encode(exchange)
	if err != nil {
		return err
	}

	conn, err := net.Dial("tcp", connect)
	if err != nil {
		return err
	}
	defer conn.Close()

	send(conn, b)

	var server DHExchange
	msgReader := bytes.NewReader(read(conn))
	decoder := gob.NewDecoder(msgReader)
	err = decoder.Decode(&server)
	if err != nil {
		panic(err)
	}

	client.GenerateSessionKey(server.PublicKey)
	fmt.Println("Session key:", sha1.Sum(client.sessionKey[:]))
	return nil
}

func send(conn net.Conn, b []byte) {
	var length bytes.Buffer
	err := binary.Write(&length, binary.LittleEndian, uint16(len(b)))
	if err != nil {
		panic(err)
	}
	conn.Write(length.Bytes())
	conn.Write(b)
}
