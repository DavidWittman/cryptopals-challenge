/*
 * Implement a SHA-1 keyed MAC
 *
 * Find a SHA-1 implementation in the language you code in.

 * Don't cheat. It won't work.
 * Do not use the SHA-1 implementation your language already provides (for
 * instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby,
 * you'd want a pure-Ruby SHA-1).
 *
 * Write a function to authenticate a message under a secret key by using a
 * secret-prefix MAC, which is simply:

 *     SHA1(key || message)
 *
 * Verify that you cannot tamper with the message without breaking the MAC
 * you've produced, and that you can't produce a new MAC without knowing the
 * secret key.
 */

package set_four

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/rand"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

var SecretPrefix = []byte("\x00\x01Super Secret Prefix\x02\x03")

func ValidateSHA1(message []byte, mac string) bool {
	sha := sha1.New()
	sha.Write(SecretPrefix)
	sha.Write(message)
	h := sha.Sum(nil)
	return hex.EncodeToString(h) == mac
}

// Tamper `message` by modifying random bits in it and then comparing to
// the provided `mac`. If there is a match, an error is returned.
func TamperMessage(message []byte, mac string) error {
	for i := 0; i < len(message); i++ {
		for j := 0; j < 8; j++ {
			// Tamper bit j in byte i
			message[i] ^= (1 << uint(j))
			if ValidateSHA1(message, mac) {
				return fmt.Errorf("Tampered message matches MAC. Message: %v", message)
			}
			// Toggle bit back to what it was before
			message[i] ^= (1 << uint(j))
		}
	}
	return nil
}

// Generate random bits and try to reproduce the MAC
func RandomBytesDontMatch(mac string, iterations int) error {
	maxBytes := 1024
	for i := 0; i < iterations; i++ {
		randBytes, _ := cryptopals.GenerateRandomBytes(rand.Intn(maxBytes))
		if ValidateSHA1(randBytes, mac) {
			return fmt.Errorf("Random message matches MAC. Message: %v", randBytes)
		}
	}
	return nil
}
