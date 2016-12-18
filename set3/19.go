/*
 * Break fixed-nonce CTR mode using substitutions
 *
 * Take your CTR encrypt/decrypt function and fix its nonce value to 0.
 * Generate a random AES key.
 *
 * In successive encryptions (not in one big running CTR stream), encrypt each
 * line of the base64 decodes of the following, producing multiple independent
 * ciphertexts:
 *
 *     <Moved to ./data/19.tx>
 *
 * (This should produce 40 short CTR-encrypted ciphertexts).
 *
 * Because the CTR nonce wasn't randomized for each encryption, each ciphertext
 * has been encrypted against the same keystream. This is very bad.
 *
 * Understanding that, like most stream ciphers (including RC4, and obviously
 * any block cipher run in CTR mode), the actual "encryption" of a byte of data
 * boils down to a single XOR operation, it should be plain that:
 *
 *     CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
 *
 * And since the keystream is the same for every ciphertext:
 *
 *     CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
 *     say!")
 *
 * Attack this cryptosystem piecemeal: guess letters, use expected English
 * language frequence to validate guesses, catch common English trigrams, and
 * so on.
 *
 * Don't overthink it.
 * Points for automating this, but part of the reason I'm having you do this is
 * that I think this approach is suboptimal.
 *
 */

package set_three

import (
	"crypto/aes"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

// Splits a string on newlines, decodes w/ base64, and encrypts
// the lines in CTR block mode using the same AES key and nonce
func splitDecodeAndEncrypt(text string) ([][]byte, error) {
	var results [][]byte

	block, err := aes.NewCipher(cryptopals.RANDOM_KEY)
	if err != nil {
		panic(err)
	}

	lines, err := cryptopals.ReadAllBase64Lines("./data/19.txt")
	if err != nil {
		panic(err)
	}

	for _, line := range lines {
		blockMode := cryptopals.NewCTR(block, 0)
		encrypted := make([]byte, len(line))
		blockMode.CryptBlocks(encrypted, line)
		results = append(results, encrypted)
	}

	return results, nil
}

// Returns the longest byte slice in a 2d byte-slice
// In case of a tie, the element with the lowest index wins
func findLongest(ciphers [][]byte) []byte {
	longest := 0
	for i, cipher := range ciphers {
		if len(cipher) > len(ciphers[longest]) {
			longest = i
		}
	}
	return ciphers[longest]
}

// Naive scoring of a guess of a keystream byte
func scoreGuess(ciphers [][]byte, keyByte byte, index int) int {
	score := 0
	goodBytes := []byte("AEIOURSTLMNaeiourstlmn,.; ")
	for _, cipher := range ciphers {
		if index < len(cipher) {
			char := cipher[index] ^ keyByte
			// Short circuit scoring for non-printable bytes
			if char < 32 || char > 126 {
				return -1
			}
			// Good bytes get points!
			for _, goodByte := range goodBytes {
				if char == goodByte {
					score += 1
					break
				}
			}
		}
	}
	return score
}

// Naively attempt to guess the keystream bytes of a fixed nonce (and key)
// CTR cipher. Takes a 2d byte-slice of ciphers as its only argument.
//
// Rather than do the suggested trigram method here, I just picked the longest
// cipher and started guessing keystream bytes and then scoring the plaintext
// of the other ciphers.
//
// This guessing and scoring starts to break down when the number of remaining
// ciphers (because of the varying lengths) starts to drop. Some better scoring,
// possibly using trigrams/frequencies, would probably improve this. However,
// based on the description, I think
func GuessFixedNonceCTRKeystream(ciphers [][]byte) []byte {
	var keystream []byte

	longest := findLongest(ciphers)
	for i := 0; i < len(longest); i++ {
		// Guess a character for the first byte and score the result against
		// all of the other ciphers
		var bestKeyGuess byte
		bestKeyScore := 0

		// We're using the range 32 -> 126 for printable ASCII
		for guess := 32; guess <= 126; guess++ {
			keyGuess := longest[i] ^ byte(guess)
			if score := scoreGuess(ciphers, keyGuess, i); score > bestKeyScore {
				bestKeyScore = score
				bestKeyGuess = keyGuess
			}
		}
		keystream = append(keystream, byte(bestKeyGuess))
	}

	return keystream
}
