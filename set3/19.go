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
 *     SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
 *     Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
 *     RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
 *     RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
 *     SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
 *     T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
 *     T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
 *     UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
 *     QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
 *     T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
 *     VG8gcGxlYXNlIGEgY29tcGFuaW9u
 *     QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
 *     QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
 *     QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
 *     QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
 *     QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
 *     VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
 *     SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
 *     SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
 *     VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
 *     V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
 *     V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
 *     U2hlIHJvZGUgdG8gaGFycmllcnM/
 *     VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
 *     QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
 *     VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
 *     V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
 *     SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
 *     U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
 *     U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
 *     VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
 *     QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
 *     SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
 *     VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
 *     WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
 *     SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
 *     SW4gdGhlIGNhc3VhbCBjb21lZHk7
 *     SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
 *     VHJhbnNmb3JtZWQgdXR0ZXJseTo=
 *     QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
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
	"strings"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const CIPHERTEXTS = `SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=`

// Splits a string on newlines, decodes w/ base64, and encrypts
// the lines in CTR block mode using the same AES key and nonce
func splitDecodeAndEncrypt(text string) ([][]byte, error) {
	var results [][]byte

	block, err := aes.NewCipher(cryptopals.RANDOM_KEY)
	if err != nil {
		panic(err)
	}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		decoded, err := cryptopals.ReadBase64String(line)
		if err != nil {
			return [][]byte{}, nil
		}
		blockMode := cryptopals.NewCTR(block, 0)
		encrypted := make([]byte, len(decoded))
		blockMode.CryptBlocks(encrypted, []byte(decoded))
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

// I didn't do the trigram thing here. Just pick the longest cipher and start
// guessing/scoring keystream bytes against the other ciphers.
func BreakFixedNonceCTR(ciphers [][]byte) []byte {
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
