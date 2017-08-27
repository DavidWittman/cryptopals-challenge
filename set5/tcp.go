package set_five

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"io"
	"net"
)

const (
	TCP_DHE          = 0x1
	TCP_BYTES        = 0x2
	TCP_SRP_EXCHANGE = 0x3
)

type TCPClient struct {
	conn net.Conn
}

func (c *TCPClient) encode(data interface{}) ([]byte, error) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)
	if err := encoder.Encode(data); err != nil {
		return []byte{}, err
	}
	return b.Bytes(), nil
}

func (c *TCPClient) read() []byte {
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

// TODO(dw): I don't really like the way I'm mapping types to constants, but it works
func (c *TCPClient) ReadMessage(kind byte) interface{} {
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

	case TCP_SRP_EXCHANGE:
		var decoded SRPExchange
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

func (c *TCPClient) Send(data interface{}) {
	b, err := c.encode(data)
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
