/*
 * An ECB/CBC detection oracle
 *
 * Now that you have ECB and CBC working:
 *
 * Write a function to generate a random AES key; that's just 16 random bytes.
 *
 * Write a function that encrypts data under an unknown key --- that is, a
 * function that generates a random key and encrypts under it.
 *
 * The function should look like:
 *
 *     encryption_oracle(your-input)
 *     => [MEANINGLESS JIBBER JABBER]
 *
 * Under the hood, have the function append 5-10 bytes (count chosen randomly)
 * before the plaintext and 5-10 bytes after the plaintext.
 *
 * Now, have the function choose to encrypt under ECB 1/2 the time, and under
 * CBC the other half (just use random IVs each time for CBC). Use rand(2) to
 * decide which to use.
 *
 * Detect the block cipher mode the function is using each time. You should end
 * up with a piece of code that, pointed at a block box that might be
 * encrypting ECB or CBC, tells you which one is happening.
 */

package set_two

import (
	"bytes"
	"crypto/rand"
	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const KEY_SIZE = 16

// Return true or false 50% of the time
func coinflip() bool {
	random, err := GenerateRandomBytes(1)
	if err != nil {
		panic(err)
	}
	return (random[0] & byte(1)) != byte(0)
}

func GenerateRandomBytes(n int) ([]byte, error) {
	result := make([]byte, n)
	_, err := rand.Read(result)
	if err != nil {
		return []byte{}, err
	}
	return result, nil
}

// Pad `data` with byte `repeat` 5 to 10 times (random, inclusive).
// Count chosen randomly for the beginning and ending of `data`.
func bookendPad(data []byte, repeat byte) []byte {
	prefix := bytes.Repeat([]byte{repeat}, cryptopals.RandomInt(5, 10))
	suffix := bytes.Repeat([]byte{repeat}, cryptopals.RandomInt(5, 10))
	return append(prefix, append(data, suffix...)...)
}

func RandomlyEncryptECBOrCBC(data []byte) ([]byte, string, error) {
	var encrypted []byte
	var err error

	key, _ := GenerateRandomBytes(KEY_SIZE)

	data = cryptopals.PKCS7Pad(len(key), bookendPad(data, 'Z'))

	// "flip a coin" to determine if we should use ECB or CBC
	if coinflip() {
		iv, _ := GenerateRandomBytes(KEY_SIZE)
		encrypted, err = cryptopals.EncryptAESCBC(data, key, iv)
		return encrypted, "cbc", err
	} else {
		encrypted, err = cryptopals.EncryptAESECB(data, key)
		return encrypted, "ecb", err
	}
}

func DetectECBOrCBC(data []byte, keySize int) string {
	match := cryptopals.FindMatchingBlock(data, keySize)
	if len(match) > 0 {
		return "ecb"
	}
	return "cbc"
}
