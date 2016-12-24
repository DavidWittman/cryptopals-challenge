/*
 * Create the MT19937 stream cipher and break it
 *
 * You can create a trivial stream cipher out of any PRNG; use it to generate a
 * sequence of 8 bit outputs and call those outputs a keystream. XOR each byte
 * of plaintext with each successive byte of keystream.
 *
 * Write the function that does this for MT19937 using a 16-bit seed. Verify
 * that you can encrypt and decrypt properly. This code should look similar to
 * your CTR code.
 *
 * Use your function to encrypt a known plaintext (say, 14 consecutive 'A'
 * characters) prefixed by a random number of random characters.
 *
 * From the ciphertext, recover the "key" (the 16 bit seed).
 *
 * Use the same idea to generate a random "password reset token" using MT19937
 * seeded from the current time.
 *
 * Write a function to check if any given password token is actually the product
 * of an MT19937 PRNG seeded with the current time.
 *
 */

package set_three

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func (mt *mersenneTwister) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("mt19937Cipher: output smaller than input")
	}

	for i, b := range src {
		// XOR plaintext with 1 byte of output from MT
		dst[i] = b ^ byte(mt.Extract()&0xFF)
	}
}

func mtOracle(plaintext []byte) []byte {
	key := uint16(rand.Intn(math.MaxUint16))

	randomPrefix, _ := cryptopals.GenerateRandomBytes(rand.Intn(32))
	plaintext = append(randomPrefix, plaintext...)
	encrypted := make([]byte, len(plaintext))

	mt := NewMersenneTwister()
	mt.Seed(uint32(key))
	mt.CryptBlocks(encrypted, plaintext)

	return encrypted
}

func BruteForceMersenneKey(cipher, knownPlaintext []byte) (uint16, error) {
	mt := NewMersenneTwister()
	decrypted := make([]byte, len(cipher))
	// The cipher is padded with random bytes on the front
	start := len(cipher) - len(knownPlaintext)

	for i := uint16(0); i < math.MaxUint16; i++ {
		mt.Seed(uint32(i))
		mt.CryptBlocks(decrypted, cipher)
		if bytes.Compare(knownPlaintext, decrypted[start:]) == 0 {
			return i, nil
		}
	}

	return uint16(0), fmt.Errorf("Unable to brute force key")
}
