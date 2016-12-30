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
)

var SecretPrefix = []byte("\x00\x01Super Secret Prefix\x02\x03")

func ValidateSHA1(message []byte, mac string) bool {
	sha := sha1.New()
	sha.Write(SecretPrefix)
	sha.Write(message)
	h := sha.Sum(nil)
	return hex.EncodeToString(h) == mac
}

// TODO(dw): Tamper with the message by modifying bits in it without reproducing the MAC
// Generate random bits and try to reproduce the MAC
