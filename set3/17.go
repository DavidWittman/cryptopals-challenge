/*
 * The CBC padding oracle
 *
 * This is the best-known attack on modern block-cipher cryptography.
 *
 * Combine your padding code and your CBC code to write two functions.
 *
 * The first function should select at random one of the following 10 strings:
 *
 *     MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
 *     MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
 *     MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
 *     MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
 *     MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
 *     MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
 *     MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
 *     MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
 *     MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
 *     MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
 *
 * ... generate a random AES key (which it should save for all future
 * encryptions), pad the string out to the 16-byte AES block size and
 * CBC-encrypt it under that key, providing the caller the ciphertext and IV.
 *
 * The second function should consume the ciphertext produced by the first
 * function, decrypt it, check its padding, and return true or false depending
 * on whether the padding is valid.
 *
 * What you're doing here.
 * This pair of functions approximates AES-CBC encryption as its deployed
 * serverside in web applications; the second function models the server's
 * consumption of an encrypted session token, as if it was a cookie.
 *
 * It turns out that it's possible to decrypt the ciphertexts provided by the
 * first function.
 *
 * The decryption here depends on a side-channel leak by the decryption
 * function. The leak is the error message that the padding is valid or not.
 *
 * You can find 100 web pages on how this attack works, so I won't
 * re-explain it. What I'll say is this:
 *
 * The fundamental insight behind this attack is that the byte 01h is valid
 * padding, and occur in 1/256 trials of "randomized" plaintexts produced by
 * decrypting a tampered ciphertext.
 *
 * 02h in isolation is not valid padding.
 *
 * 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
 *
 * 03h 03h 03h is even less likely.
 *
 * So you can assume that if you corrupt a decryption AND it had valid padding,
 * you know what that padding byte is.
 *
 * It is easy to get tripped up on the fact that CBC plaintexts are "padded".
 * *Padding oracles have nothing to do with the actual padding on a CBC
 * plaintext*. It's an attack that targets a specific bit of code that handles
 * decryption. You can mount a padding oracle on any CBC block, whether it's
 * padded or not.
 */

package set_three

import (
	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

type PaddingOracle func([]byte) bool

var iv = []byte("YELLOW SUBMARINE")

func EncryptRandomString() []byte {
	possibilities := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	//i := cryptopals.RandomInt(0, len(possibilities)-1)
	i := 0
	encrypted, err := cryptopals.EncryptAESCBC([]byte(possibilities[i]), cryptopals.RANDOM_KEY, iv)
	if err != nil {
		panic(err)
	}
	return encrypted
}

func CBCPaddingOracle(ciphertext []byte) bool {
	decrypted, err := cryptopals.DecryptAESCBC(ciphertext, cryptopals.RANDOM_KEY, iv)
	if err != nil {
		panic(err)
	}
	return cryptopals.IsPKCS7Padded(decrypted)
}

// Create a byte slice which when XORed against i2, produces
// padLength bytes at the end of the result which are one byte
// short of making a full PKCS7 pad.
func generateInjectionPad(i2 []byte, padLength int) []byte {
	blockSize := len(i2)
	result, _ := cryptopals.GenerateRandomBytes(blockSize)

	if padLength < 1 {
		panic("generateInjectionPad: invalid padLength")
	}

	// Set all the bytes to padLength + 1
	// i.e. If we're padding 3 bytes, we want the last 4 bytes to be 0x04
	for i := 1; i <= padLength; i++ {
		result[blockSize-i] = i2[blockSize-i] ^ byte(padLength+1)
	}

	return result
}

/* Brute force the plaintext of C2 by exploiting the padding oracle
 *
 *  Let:
 *      C1, C2   Ciphertext blocks 1 and 2
 *      C1'      The block we are injecting into the padding oracle to determine
 *               values in P2
 *      I2       Intermediate block 2. This is the decrypted block 2 _before_
 *               it is XORed with C1.
 *      P2       Plaintext block 2
 *
 *  1. Generate a random injection block, C1', and starting with the last byte
 *     try all possible values until the PaddingOracle returns true.
 *
 *     i.e. C1'[15] ^ I2[15] == 0x01
 *
 *  2. We can now determine I2[15] by XORing our known values:
 *
 *         I2[15] = C1'[15] ^ 0x01
 *
 *  3. Which now allows us to determine the plaintext:
 *
 *         P2[15] = C1[15] ^ I2[15]
 *
 *  4. Do the same thing for the remaining bytes in P2. Start by determining
 *     what we must set C1'[i] should be set to to make P2'[i] equal the
 *     correct padding value.
 *
 *         C1'[15] = I2[15] ^ 0x02
 */
func BruteForceBlock(c1, c2 []byte, oracle PaddingOracle) []byte {
	if len(c1) != len(c2) {
		panic("Block lengths do not match")
	}
	blockSize := len(c2)

	// This is the block which we will be injecting as C1'
	inject, _ := cryptopals.GenerateRandomBytes(blockSize)

	// The intermediate block which is XORed with the decrypted text
	i2 := make([]byte, blockSize)

	// The result
	plaintext := make([]byte, blockSize)

	for i := blockSize - 1; i >= 0; i-- {
		padLength := blockSize - (i % blockSize)
		// Generate values for inject[i] until we find a valid pad
		for j := 0; j < 256; j++ {
			inject[i] = byte(j)
			if oracle(append(inject, c2...)) {
				// XOR the injected byte with the correct pad value (length)
				// to determine the intermediate value
				i2[i] = byte(j ^ padLength)
				// Now that we know the intermediate value and the
				// ciphertext of the preceding block, we can determine
				// the plaintext value
				plaintext[i] = i2[i] ^ c1[i]
				inject = generateInjectionPad(i2, padLength)

				break
			}
		}
	}

	return plaintext
}

// We can use the padding oracle and some intercepted ciphertext to manipulate
// inputs of blocks until they yield padded plaintext.
func BruteForcePaddingOracle(ciphertext []byte, oracle PaddingOracle) []byte {
	var result []byte
	blockSize := 16
	blocks := cryptopals.SplitBytes(ciphertext, blockSize)
	for i := 1; i < len(blocks); i++ {
		result = append(result, BruteForceBlock(blocks[i-1], blocks[i], oracle)...)
	}
	return result
}
