package set_five

import (
	"math/big"
)

type SRPExchange struct {
	n, g, k  big.Int
	Email    string
	password string
}

type SRPClient struct {
	// Embed the TCPClient
	*TCPClient
}

func (c *SRPClient) ReadSRPExchange() SRPExchange {
	b := c.ReadMessage(TCP_SRP_EXCHANGE)
	return b.(SRPExchange)
}
