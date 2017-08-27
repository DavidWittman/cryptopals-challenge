package set_five

import (
	"log"
	"math/big"
	"net"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const (
	KEYSIZE = 16
)

type DHExchange struct {
	Group     *DHGroup
	PublicKey *big.Int
}

type DHClient struct {
	Name    string
	conn    *TCPClient
	session *DHSession
}

func NewDHClient(name string, conn net.Conn, session *DHSession) *DHClient {
	return &DHClient{
		name,
		&TCPClient{conn},
		session,
	}
}

func (c *DHClient) ReadDHE() DHExchange {
	bob := c.conn.ReadMessage(TCP_DHE)
	return bob.(DHExchange)
}

func (c *DHClient) ReadEncrypted() ([]byte, error) {
	key := c.session.sha1SessionKey[:KEYSIZE]
	m := c.conn.ReadMessage(TCP_BYTES)
	blob := m.([]byte)
	cipher, iv := blob[:len(blob)-KEYSIZE], blob[len(blob)-KEYSIZE:]

	message, err := cryptopals.DecryptAESCBC(cipher, key, iv)
	if err != nil {
		return []byte{}, err
	}

	unpadded := cryptopals.MaybePKCS7Unpad(message)
	log.Println(c.Name, "received message:", string(unpadded))
	return unpadded, nil
}

func (c *DHClient) SendEncrypted(b []byte) error {
	log.Println(c.Name, "is sending an encrypted message")
	key := c.session.sha1SessionKey[:KEYSIZE]
	iv, _ := cryptopals.GenerateRandomBytes(KEYSIZE)
	cipher, err := cryptopals.EncryptAESCBC(b, key, iv)
	if err != nil {
		return err
	}
	c.conn.Send(append(cipher, iv...))
	return nil
}
