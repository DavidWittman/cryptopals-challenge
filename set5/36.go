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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"net"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const (
	EMAIL    = "whitfield@example.com"
	PASSWORD = "password123"
	k        = 3
)

type SRPLogin struct {
	Email string
	A     *big.Int
}

type SRPLoginResponse struct {
	Salt []byte
	B    *big.Int
}

type SRPClient struct {
	a *big.Int
	// Embed the TCPClient
	*TCPClient
}

func NewSRPClient(addr string) (*SRPClient, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Generate a = RANDOM % p
	p, _, _ := GetNISTParams()
	random := big.NewInt(int64(cryptopals.RandomInt(1, DH_MAX_RANDOM)))
	a := new(big.Int).Mod(random, p)

	client := &SRPClient{a, &TCPClient{conn}}
	return client, nil
}

func (c *SRPClient) Login(password string) bool {
	n, g, _ := GetNISTParams()

	A := new(big.Int).Exp(g, c.a, n)

	c.Send(&SRPLogin{
		Email: EMAIL,
		A:     A,
	})

	r := c.ReadMessage(TCP_SRP_LOGIN_RESP)
	resp := r.(SRPLoginResponse)

	// Compute string uH = SHA256(A|B), u = integer of uH
	uH := sha256.Sum256(append(A.Bytes(), resp.B.Bytes()...))
	u := SHA256ToBigInt(uH[:])

	// Generate string xH=SHA256(salt|password)
	xH := SaltAndHash(PASSWORD)
	x := SHA256ToBigInt(xH)

	// Generate S = (B - k * g**x)**(a + u * x) % N
	gx := new(big.Int).Exp(g, x, nil)
	aux := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(new(big.Int).Sub(resp.B, new(big.Int).Mul(big.NewInt(k), gx)), aux, n)
	K := sha256.Sum256(S.Bytes())

	// Generate HMAC(K, salt) and send to S
	mac := hmac.New(sha256.New, K[:])
	mac.Write(cryptopals.RANDOM_KEY)
	c.Send(mac.Sum(nil))

	okResp := c.ReadMessage(TCP_BYTES)
	ok := okResp.([]byte)

	if string(ok) == "OK" {
		return true
	}

	return false
}

type SRPServer struct {
	v *big.Int
	*TCPClient
}

func SaltAndHash(text string) []byte {
	salt := cryptopals.RANDOM_KEY
	sum := sha256.Sum256(append(salt, []byte(text)...))
	return sum[:]
}

func SHA256ToBigInt(sum []byte) *big.Int {
	i, _ := binary.Varint(sum)
	// NB: Take the absolute value so we don't do negative exponentiation
	return new(big.Int).Abs(big.NewInt(i))
}

func (s *SRPServer) Handler(conn net.Conn) error {
	s.TCPClient = &TCPClient{conn}

	xH := SaltAndHash(PASSWORD)
	x := SHA256ToBigInt(xH)

	// Generate v
	n, g, _ := GetNISTParams()
	s.v = new(big.Int).Exp(g, x, n)

	l := s.ReadMessage(TCP_SRP_LOGIN)
	// TODO(dw): Need login details later
	login := l.(SRPLogin)

	// Generate b = RANDOM % p (p == n here)
	random := big.NewInt(int64(cryptopals.RandomInt(1, DH_MAX_RANDOM)))
	b := new(big.Int).Mod(random, n)

	// Generate B = kv + g**b % N
	kv := new(big.Int).Mul(big.NewInt(k), s.v)
	B := new(big.Int).Add(kv, new(big.Int).Exp(g, b, n))

	s.Send(&SRPLoginResponse{cryptopals.RANDOM_KEY, B})

	// Compute string uH = SHA256(A|B), u = integer of uH
	uH := sha256.Sum256(append(login.A.Bytes(), B.Bytes()...))
	u := SHA256ToBigInt(uH[:])

	// Generate S = (A * v**u) ** b % N
	S := new(big.Int).Exp(new(big.Int).Mul(login.A, new(big.Int).Exp(s.v, u, nil)), b, n)
	K := sha256.Sum256(S.Bytes())

	mac := hmac.New(sha256.New, K[:])
	mac.Write(cryptopals.RANDOM_KEY)
	expectedMAC := mac.Sum(nil)

	challengeMsg := s.ReadMessage(TCP_BYTES)
	challenge := challengeMsg.([]byte)

	if hmac.Equal(expectedMAC, challenge) {
		s.Send([]byte("OK"))
	} else {
		s.Send([]byte("FAIL"))
	}

	return nil
}
