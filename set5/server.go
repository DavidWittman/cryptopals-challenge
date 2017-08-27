package set_five

import (
	"log"
	"net"
)

func ListenForConnection(listen string) (net.Conn, error) {
	socket, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	defer socket.Close()

	conn, err := socket.Accept()
	if err != nil {
		log.Println("Error establishing connection:", err)
		return nil, err
	}
	return conn, nil
}

func StartServer(handler func(net.Conn) error, listen string) {
	conn, err := ListenForConnection(listen)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	err = handler(conn)
	if err != nil {
		panic(err)
	}
}

func StartMITMServer(handler func(net.Conn, net.Conn) error, listen, dest string) {
	conn, err := ListenForConnection(listen)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Establish connection with client
	client, err := net.Dial("tcp", dest)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	err = handler(conn, client)
	if err != nil {
		panic(err)
	}
}
