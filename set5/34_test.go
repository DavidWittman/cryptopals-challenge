package set_five

import (
	"testing"
)

func TestDHExchange(t *testing.T) {
	listen := ":3000"
	go StartServer(listen)
	_ = Client("localhost" + listen)
}
