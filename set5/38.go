/*
 * Offline dictionary attack on simplified SRP
 *
 * S
 *     x = SHA256(salt|password)
 *     v = g**x % n
 *
 * C->S
 *     I, A = g**a % n
 *
 * S->C
 *     salt, B = g**b % n, u = 128 bit random number
 *
 * C
 *     x = SHA256(salt|password)
 *     S = B**(a + ux) % n
 *     K = SHA256(S)
 *
 * S
 *     S = (A * v ** u)**b % n
 *     K = SHA256(S)
 *
 * C->S
 *     Send HMAC-SHA256(K, salt)
 *
 * S->C
 *     Send "OK" if HMAC-SHA256(K, salt) validates
 *
 * Note that in this protocol, the server's "B" parameter doesn't depend on the
 * password (it's just a Diffie Hellman public key).
 *
 * Make sure the protocol works given a valid password.
 *
 * Now, run the protocol as a MITM attacker: pose as the server and use
 * arbitrary values for b, B, u, and salt.
 *
 * Crack the password from A's HMAC-SHA256(K, salt).
 *
 * NOTE(dw): The reason we can brute force the client's hash here and not in
 *           Challenge 36 is because B (and therefore the MAC we receive from
 *           the client is based on the password. So we would need to pass the
 *           correct password in B in order to ever brute force the hash.
 */

package set_five

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"
	"math/big"
	"net"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

type SimpleSRPLoginResponse struct {
	Salt []byte
	B, U *big.Int
}

func (c *SRPClient) SimpleLogin(password string) bool {
	n, g, _ := GetNISTParams()

	A := new(big.Int).Exp(g, c.a, n)

	c.Send(&SRPLogin{
		Email: EMAIL,
		A:     A,
	})

	r := c.ReadMessage(TCP_SIMPLE_SRP_LOGIN_RESP)
	resp := r.(SimpleSRPLoginResponse)

	// Generate string xH=SHA256(salt|password)
	xH := SaltAndHash(password)
	x := SHA256ToBigInt(xH)

	// Generate S = B**(a + ux) % n
	aux := new(big.Int).Add(c.a, new(big.Int).Mul(resp.U, x))
	S := new(big.Int).Exp(resp.B, aux, n)
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

func (s *SRPServer) SimpleHandler(conn net.Conn) error {
	s.TCPClient = &TCPClient{conn}

	xH := SaltAndHash(PASSWORD)
	x := SHA256ToBigInt(xH)

	// Generate v
	n, g, _ := GetNISTParams()
	s.v = new(big.Int).Exp(g, x, n)

	l := s.ReadMessage(TCP_SRP_LOGIN)
	login := l.(SRPLogin)

	// Generate b = RANDOM % p (p == n here)
	random := big.NewInt(int64(cryptopals.RandomInt(1, DH_MAX_RANDOM)))
	b := new(big.Int).Mod(random, n)

	// Generate B = g**b % n
	B := new(big.Int).Exp(g, b, n)

	// u = 128 bit random number
	// TODO: More intelligent max for the random here?
	u := big.NewInt(int64(cryptopals.RandomInt(1, DH_MAX_RANDOM)))
	s.Send(&SimpleSRPLoginResponse{cryptopals.RANDOM_KEY, B, u})

	// Generate S = (A * v ** u)**b % n
	vu := new(big.Int).Exp(s.v, u, n)
	Avu := new(big.Int).Mul(login.A, vu)
	S := new(big.Int).Exp(Avu, b, n)
	log.Printf("Server S: %v", S)
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

func (s *SRPServer) SimpleHandlerMITM(conn net.Conn) error {
	s.TCPClient = &TCPClient{conn}

	// We don't know the password, so just salt nothing
	xH := SaltAndHash("")
	x := SHA256ToBigInt(xH)

	// Generate v
	n, g, _ := GetNISTParams()
	s.v = new(big.Int).Exp(g, x, n)

	l := s.ReadMessage(TCP_SRP_LOGIN)
	login := l.(SRPLogin)

	// Generate b = RANDOM % p (p == n here)
	random := big.NewInt(int64(cryptopals.RandomInt(1, DH_MAX_RANDOM)))
	b := new(big.Int).Mod(random, n)

	// Generate B = g**b % n
	B := new(big.Int).Exp(g, b, n)

	// u = 128 bit random number
	u := big.NewInt(int64(cryptopals.RandomInt(1, DH_MAX_RANDOM)))
	resp := &SimpleSRPLoginResponse{cryptopals.RANDOM_KEY, B, u}
	s.Send(resp)

	// Read MAC from the client and brute force it
	challengeMsg := s.ReadMessage(TCP_BYTES)
	challenge := challengeMsg.([]byte)

	log.Printf("Attempting to crack password")
	// TODO: I hate having to pass all these params, maybe they should be in the struct
	s.Crack(challenge, login.A, b, resp)
	// We don't care about checking the password; just respond with OK
	s.Send([]byte("OK"))

	return nil
}

func (s *SRPServer) Crack(challenge []byte, A *big.Int, b *big.Int, resp *SimpleSRPLoginResponse) {
	var wordlist []string = []string{"password", "123456", "office2005", "password123", "dinero"}
	n, _, _ := GetNISTParams()
	for _, word := range wordlist {
		xH := SaltAndHash(word)
		x := SHA256ToBigInt(xH)

		// Generate S = B**(a + ux) % n
		// Only, we don't know `a`, but we can expand this equation and make it:
		//     S = (B**a) * (B**ux)
		// And then substitute A**b (which we know) for B**a, a la DHE
		//     S = (A**b) * (B**ux)
		S := new(big.Int).Exp(A, b, n)
		Bux := new(big.Int).Exp(resp.B, new(big.Int).Mul(resp.U, x), n)
		S.Mul(S, Bux)
		K := sha256.Sum256(S.Bytes())

		// Generate HMAC(K, salt)
		mac := hmac.New(sha256.New, K[:])
		mac.Write(resp.Salt)
		guess := mac.Sum(nil)

		if hmac.Equal(challenge, guess) {
			log.Printf("Password found: %s", word)
			break
		}
	}
}
