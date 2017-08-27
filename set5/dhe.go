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
	TCP_DHE   = 0x1
	TCP_BYTES = 0x2

	KEYSIZE = 16
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

func encode(data interface{}) ([]byte, error) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)
	if err := encoder.Encode(data); err != nil {
		return []byte{}, err
	}
	return b.Bytes(), nil
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

func (c *DHClient) ReadDHE() DHExchange {
	bob := c.ReadMessage(TCP_DHE)
	return bob.(DHExchange)
}

func (c *DHClient) ReadMessage(kind byte) interface{} {
	msgReader := bytes.NewReader(c.read())
	decoder := gob.NewDecoder(msgReader)
	switch kind {
	case TCP_DHE:
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
	m := c.ReadMessage(TCP_BYTES)
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
	c.Send(append(cipher, iv...))
	return nil
}

func (c *DHClient) Send(data interface{}) {
	b, err := encode(data)
	if err != nil {
		panic(err)
	}

	var length bytes.Buffer
	err = binary.Write(&length, binary.LittleEndian, uint16(len(b)))
	if err != nil {
		panic(err)
	}
	c.conn.Write(length.Bytes())
	c.conn.Write(b)
}
