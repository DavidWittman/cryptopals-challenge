/*
 * Implement unpadded message recovery oracle
 *
 * Nate Lawson says we should stop calling it "RSA padding" and start calling it
 * "RSA armoring". Here's why.
 *
 * Imagine a web application, again with the Javascript encryption, taking
 * RSA-encrypted messages which (again: Javascript) aren't padded before
 * encryption at all.
 *
 * You can submit an arbitrary RSA blob and the server will return plaintext.
 * But you can't submit the same message twice: let's say the server keeps
 * hashes of previous messages for some liveness interval, and that the message
 * has an embedded timestamp:
 *
 *     {
 *       time: 1356304276,
 *       social: '555-55-5555',
 *     }
 *
 * You'd like to capture other people's messages and use the server to decrypt
 * them. But when you try, the server takes the hash of the ciphertext and uses
 * it to reject the request. Any bit you flip in the ciphertext irrevocably
 * scrambles the decryption.
 *
 * This turns out to be trivially breakable:
 *
 *  - Capture the ciphertext C
 *  - Let N and E be the public modulus and exponent respectively
 *  - Let S be a random number > 1 mod N. Doesn't matter what.
 *  - Now:
 *
 *        C' = ((S**E mod N) C) mod N
 *
 *  - Submit C', which appears totally different from C, to the server,
 *    recovering P', which appears totally different from P
 *
 *  - Now:
 *              P'
 *        P = -----  mod N
 *              S
 *
 * Oops!
 *
 * Implement that attack.
 *
 * Careful about division in cyclic groups.
 * Remember: you don't simply divide mod N; you multiply by the multiplicative
 * inverse mod N. So you'll need a modinv() function.
 *
 */

package set6

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/DavidWittman/cryptopals-challenge/set5"
)

type RSAOracle struct {
	privateKey *rsa.PrivateKey
	seenMsgs   map[[sha256.Size]byte]bool
}

func NewRSAOracle() *RSAOracle {
	privKey, err := set_five.RSAGenerate()
	if err != nil {
		panic(err)
	}

	return &RSAOracle{
		privateKey: privKey,
		seenMsgs:   make(map[[sha256.Size]byte]bool),
	}
}

func (r *RSAOracle) Encrypt(blob []byte) []byte {
	return set_five.RSAEncrypt(blob, &r.privateKey.PublicKey)
}

func (r *RSAOracle) Decrypt(blob []byte) ([]byte, error) {
	hash := sha256.Sum256(blob)

	if _, ok := r.seenMsgs[hash]; ok {
		return []byte{}, fmt.Errorf("This message has already been seen and will not be decrypted again")
	}

	r.seenMsgs[hash] = true

	return set_five.RSADecrypt(blob, r.privateKey), nil
}

func (r *RSAOracle) GetPublicKey() *rsa.PublicKey {
	return &r.privateKey.PublicKey
}

func RecoverMessage(cipher []byte, r *RSAOracle) []byte {
	pub := r.GetPublicKey()
	// Cipher as bigint
	c := new(big.Int).SetBytes(cipher)

	// "Random" number
	s := big.NewInt(42)
	// S**E mod N
	S := new(big.Int).Exp(s, big.NewInt(int64(pub.E)), pub.N)

	// C * S**E mod N
	Cprime := new(big.Int)
	Cprime.Mul(c, S).Mod(Cprime, pub.N)

	Pbytes, err := r.Decrypt(Cprime.Bytes())
	if err != nil {
		panic(err)
	}

	// P' * ModInv(s, N)
	Pprime := new(big.Int).SetBytes(Pbytes)
	P := new(big.Int).Mul(Pprime, new(big.Int).ModInverse(s, pub.N))

	return P.Mod(P, pub.N).Bytes()
}
