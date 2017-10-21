/*
 * Break SRP with a zero key
 *
 * Get your SRP working in an actual client-server setting. "Log in" with a
 * valid password using the protocol.
 *
 * Now log in without your password by having the client send 0 as its "A"
 * value. What does this to the "S" value that both sides compute?
 *
 * Now log in without your password by having the client send N, N*2, &c.
 *
 * Cryptanalytic MVP award
 *
 * Trevor Perrin and Nate Lawson taught us this attack 7 years ago. It is
 * excellent. Attacks on DH are tricky to "operationalize". But this attack
 * uses the same concepts, and results in auth bypass. Almost every
 * implementation of SRP we've ever seen has this flaw; if you see a new one,
 * go look for this bug.
 *
 */

package set_five

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"
	"math/big"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func (c *SRPClient) MaliciousLogin(password string, A *big.Int) bool {
	c.Send(&SRPLogin{
		Email: EMAIL,
		A:     A,
	})

	r := c.ReadMessage(TCP_SRP_LOGIN_RESP)
	_ = r.(SRPLoginResponse)

	// Skip all that mumbo-jumbo and just set S = 0
	S := big.NewInt(0)
	log.Printf("Client S: %v", S)
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
