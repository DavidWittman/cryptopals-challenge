/*
 * Byte-at-a-time ECB decryption (Simple)
 *
 * Copy your oracle function to a new function that encrypts buffers under ECB
 * mode using a consistent but unknown key (for instance, assign a single
 * random key, once, to a global variable).
 *
 * Now take that same function and have it append to the plaintext, BEFORE
 * ENCRYPTING, the following string:
 *
 *     Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
 *     aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
 *     dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
 *     YnkK
 *
 * Spoiler alert: Do not decode this string now. Don't do it.
 *
 * Base64 decode the string before appending it. Do not base64 decode the
 * string by hand; make your code do it. The point is that you don't know
 * its contents.
 *
 * What you have now is a function that produces:
 *
 *     AES-128-ECB(your-string || unknown-string, random-key)
 *
 * It turns out: you can decrypt "unknown-string" with repeated calls to
 * the oracle function!
 *
 * Here's roughly how:
 *
 *   1. Feed identical bytes of your-string to the function 1 at a time ---
 *      start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover
 *      the block size of the cipher. You know it, but do this step anyway.
 *   2. Detect that the function is using ECB. You already know, but do this
 *      step anyways.
 *   3. Knowing the block size, craft an input block that is exactly 1 byte
 *      short (for instance, if the block size is 8 bytes, make "AAAAAAA").
 *      Think about what the oracle function is going to put in that last byte
 *      position.
 *   4. Make a dictionary of every possible last byte by feeding different
 *      strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
 *      "AAAAAAAC", remembering the first block of each invocation.
 *   5. Match the output of the one-byte-short input to one of the entries in
 *      your dictionary. You've now discovered the first byte of unknown-string.
 *   6. Repeat for the next byte.
 *
 * Notes:
 *
 *     0 1 2 3 4 5 6 7
 *     A A A A A A A X
 *
 *	   Generate a lookup table for all values of X, then run the Encryption Oracle
 *     with _only_ the padding and let it fill in the rest with the secret bytes.
 *     Then lookup the block which the Oracle created in your lookup table and
 *     proceed to the next byte. Let's pretend our discovered byte was `s`:
 *
 *     0 1 2 3 4 5 6 7
 *     A A A A A A s X
 *
 *     Our new lookup table generates all values for X here, then we run the
 *     Encryption Oracle with 6 A's, let it fill in the 7th byte with the already
 *     known letter `s`, and our mystery byte in 8. Now lookup in your table and
 *     discover the second byte. Rinse and repeat for all blocks.
 *
 *     0 1 2 3 4 5 6 7
 *     A A A A A s e X
 *     ...
 *     s e c r e t s t
 *
 *     Next Block:
 *
 *     0 1 2 3 4 5 6 7  8 9 0 1 2 3 4 5
 *     A A A A A A A s  e c r e t s t X
 *     A A A A A A s e  c r e t s t u X
 *     A A A A A s e c  r e t s t u f X
 *	   ...
 *     s e c r e t s t  u f f o o b a r
 */

package set_two

import (
	"bytes"
	"encoding/base64"
	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
	"io/ioutil"
	"strings"
)

var RANDOM_KEY []byte

type EncryptionOracle func([]byte) []byte

func init() {
	var err error
	RANDOM_KEY, err = GenerateRandomBytes(16)
	if err != nil {
		panic(err)
	}
}

func DetermineBlockSize(oracle EncryptionOracle) int {
	prevLen := 0
	for i := 1; ; i++ {
		result := oracle(bytes.Repeat([]byte("A"), i))
		if len(result) > prevLen {
			// Block size increased. Set prevLen if it's the first time,
			// otherwise compute the difference in block sizes.
			if prevLen != 0 {
				return len(result) - prevLen
			}
			prevLen = len(result)
		}
	}
}

func IsOracleEBC(oracle EncryptionOracle, blockSize int) bool {
	encrypted := oracle(bytes.Repeat([]byte("A"), 1024))
	return len(cryptopals.FindMatchingBlock(encrypted, blockSize)) > 0
}

func Oracle(data []byte) []byte {
	unknownString := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXk
gaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`

	unknownReader := strings.NewReader(unknownString)
	unknownBytes, err := ioutil.ReadAll(
		base64.NewDecoder(base64.StdEncoding, unknownReader))
	if err != nil {
		return []byte{}
	}

	data = append(data, unknownBytes...)
	result, _ := cryptopals.EncryptAESECB(data, RANDOM_KEY)
	return result
}

func GenerateByteLookupTable(oracle EncryptionOracle, prefix []byte, blockStart, blockEnd int) map[string]byte {
	var i byte
	result := make(map[string]byte)

	// We only need 0-128 for most characters
	for i = 0; i < 128; i++ {
		known := append(prefix, i)
		shortBlock := Oracle(known)[blockStart:blockEnd]
		// Correlate this block with the byte `i`
		result[string(shortBlock)] = i
	}

	return result
}

func BreakECB(oracle EncryptionOracle) []byte {
	var decrypted []byte

	blockSize := DetermineBlockSize(oracle)
	emptyCipherLen := len(Oracle([]byte{}))

	for len(decrypted) < emptyCipherLen {
		blockStart := len(decrypted)
		blockEnd := blockStart + blockSize

		for i := blockSize - 1; i >= 0; i-- {
			// Craft a string of every byte we know thus far, leaving the only unknown character
			// as the last byte in a block.
			bunchOfAs := bytes.Repeat([]byte("A"), i)
			knownPrefix := append(bunchOfAs, decrypted...)
			lookup := GenerateByteLookupTable(oracle, knownPrefix, blockStart, blockEnd)

			// Now generate the actual encrypted block and look it up in our table
			// We use only our padding here (bunchOfAs) to let the Oracle fill in the remaining bytes
			// with the secret text and we can compare them against our lookup table.
			block := Oracle(bunchOfAs)[blockStart:blockEnd]
			decrypted = append(decrypted, lookup[string(block)])
		}
	}

	return decrypted
}
