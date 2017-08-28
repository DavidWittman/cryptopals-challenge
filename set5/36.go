/*
 * Implement Secure Remote Password (SRP)
 * To understand SRP, look at how you generate an AES key from DH; now, just
 * observe you can do the "opposite" operation an generate a numeric parameter
 * from a hash. Then:
 *
 * Replace A and B with C and S (client & server)
 *
 * C & S
 *     Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
 * S
 *     1. Generate salt as random integer
 *     2. Generate string xH=SHA256(salt|password)
 * 	   3. Convert xH to integer x somehow (put 0x on hexdigest)
 *     4. Generate v=g**x % N
 *     5. Save everything but x, xH
 * C->S
 *     Send I, A=g**a % N (a la Diffie Hellman)
 * S->C
 *     Send salt, B=kv + g**b % N
 * S, C
 *     Compute string uH = SHA256(A|B), u = integer of uH
 * C
 *     1. Generate string xH=SHA256(salt|password)
 *     2. Convert xH to integer x somehow (put 0x on hexdigest)
 *     3. Generate S = (B - k * g**x)**(a + u * x) % N
 *     4. Generate K = SHA256(S)
 * S
 *     1. Generate S = (A * v**u) ** b % N
 *     1. Generate K = SHA256(S)
 * C->S
 *     Send HMAC-SHA256(K, salt)
 * S->C
 *     Send "OK" if HMAC-SHA256(K, salt) validates
 *
 * You're going to want to do this at a REPL of some sort; it may take a couple
 * tries.
 *
 * It doesn't matter how you go from integer to string or string to integer
 * (where things are going in or out of SHA256) as long as you do it
 * consistently. I tested by using the ASCII decimal representation of integers
 * as input to SHA256, and by converting the hexdigest to an integer when
 * processing its output.
 *
 * This is basically Diffie Hellman with a tweak of mixing the password into
 * the public keys. The server also takes an extra step to avoid storing an
 * easily crackable password-equivalent.
 */

package set_five

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
	"math/big"
	"net"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const (
	EMAIL    = "whitfield@example.com"
	PASSWORD = "password123"
)

type SRPExchange struct {
	N, G, K  *big.Int
	Email    string
	Password string
}

type SRPClient struct {
	// Embed the TCPClient
	*TCPClient
}

func NewSRPClient(addr string) (*SRPClient, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client := &SRPClient{&TCPClient{conn}}

	n, g, _ := GetNISTParams()
	exchange := &SRPExchange{
		N:        n,
		G:        g,
		K:        big.NewInt(3),
		Email:    EMAIL,
		Password: PASSWORD,
	}
	client.Send(exchange)

	return client, nil
}

func (c *SRPClient) Login(password string) bool {
	return false
}

type SRPServer struct {
	v, x *big.Int
	*TCPClient
}

func HashAndSalt(text string) [sha256.Size]byte {
	salt := cryptopals.RANDOM_KEY
	return sha256.Sum256(append(salt, []byte(text)...))
}

func SHA256ToBigInt(sum [sha256.Size]byte) *big.Int {
	i, _ := binary.Varint(sum[:])
	// NB: Take the absolute value so we don't do negative exponentiation
	return new(big.Int).Abs(big.NewInt(i))
}

func (s *SRPServer) Handler(conn net.Conn) error {
	s.TCPClient = &TCPClient{conn}
	e := s.ReadMessage(TCP_SRP_EXCHANGE)
	exchange := e.(SRPExchange)

	xH := HashAndSalt(PASSWORD)
	s.x = SHA256ToBigInt(xH)

	s.v = new(big.Int).Exp(exchange.G, s.x, exchange.N)
	log.Println(s.v)

	return nil
}
