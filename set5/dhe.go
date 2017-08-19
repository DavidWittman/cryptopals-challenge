package set_five

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"io"
	"log"
	"math/big"
	"net"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const (
	DHE_MSG_EXCHANGE = 0x1
	DHE_MSG_BYTES    = 0x2
	KEYSIZE          = 16
)

type DHExchange struct {
	Group     *DHGroup
	PublicKey *big.Int
}

type DHClient struct {
	Name    string
	conn    net.Conn
	session *DHSession
}

func (c *DHClient) read() []byte {
	var length uint16

	err := binary.Read(c.conn, binary.LittleEndian, &length)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, length)
	_, err = io.ReadFull(c.conn, msg)
	if err != nil {
		panic(err)
	}

	return msg
}

// TODO(dw): Just replace this with a Handshake method and a method for
// receiving encrypted messages
func (c *DHClient) ReadMessage(kind byte) interface{} {
	msgReader := bytes.NewReader(c.read())
	decoder := gob.NewDecoder(msgReader)
	switch kind {
	case DHE_MSG_EXCHANGE:
		var decoded DHExchange
		err := decoder.Decode(&decoded)
		if err != nil {
			panic(err)
		}
		return decoded
	default:
		var decoded []byte
		err := decoder.Decode(&decoded)
		if err != nil {
			panic(err)
		}
		return decoded
	}
}

func (c *DHClient) ReadEncrypted() ([]byte, error) {
	key := c.session.sha1SessionKey[:KEYSIZE]
	m := c.ReadMessage(DHE_MSG_BYTES)
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
	encoded, err := encode(append(cipher, iv...))
	if err != nil {
		return err
	}
	c.Send(encoded)
	return nil
}

func (c *DHClient) Send(b []byte) {
	var length bytes.Buffer
	err := binary.Write(&length, binary.LittleEndian, uint16(len(b)))
	if err != nil {
		panic(err)
	}
	c.conn.Write(length.Bytes())
	c.conn.Write(b)
}
