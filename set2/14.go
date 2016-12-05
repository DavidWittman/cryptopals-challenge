/*
 * Byte-at-a-time ECB decryption (Harder)
 *
 * Take your oracle function from #12. Now generate a random count of random
 * bytes and prepend this string to every plaintext. You are now doing:
 *
 *     AES-128-ECB(
 *         random-prefix || attacker-controlled || target-bytes, random-key
 *     )
 *
 * Same goal: decrypt the target-bytes.
 *
 * Stop and think for a second.
 *
 * What's harder than challenge #12 about doing this? How would you overcome that
 * obstacle? The hint is: you're using all the tools you already have;
 * no crazy math is required.
 *
 * Think "STIMULUS" and "RESPONSE".
 */
package set_two

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"strings"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

var RANDOM_PREFIX []byte

func init() {
	length := cryptopals.RandomInt(1, 255)
	RANDOM_PREFIX, _ = cryptopals.GenerateRandomBytes(length)

}
func HarderOracle(data []byte) []byte {
	unknownString := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXk
gaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`

	unknownReader := strings.NewReader(unknownString)
	unknownBytes, err := ioutil.ReadAll(
		base64.NewDecoder(base64.StdEncoding, unknownReader))
	if err != nil {
		return []byte{}
	}

	data = append(RANDOM_PREFIX, append(data, unknownBytes...)...)
	result, _ := cryptopals.EncryptAESECB(data, cryptopals.RANDOM_KEY)
	return result
}

// Finds the position of our controlled input in the Oracle's output
// This is done by creating a block of repeating characters 2 blocks
// in length and increasing the size until we find a repeating block.
func FindStartOfInput(oracle EncryptionOracle, blockSize int) int {
	for i := blockSize * 2; i < blockSize*3; i++ {
		input := bytes.Repeat([]byte{0x01}, i)
		cipher := oracle(input)
		if index := cryptopals.FindMatchingBlock(cipher, blockSize); index != -1 {
			return index - (i % blockSize)
		}
	}

	return -1
}

func BreakHarderECBOracle(oracle EncryptionOracle) ([]byte, error) {
	var decrypted []byte

	blockSize := DetermineBlockSize(oracle)
	randomPrefixLength := FindStartOfInput(oracle, blockSize)
	// The length of our unknown bytes at the end of the Oracle output
	unknownLength := len(oracle([]byte{})) - randomPrefixLength

	// Pad the front of our input so that we're block-aligned
	offset := blockSize - (randomPrefixLength % blockSize)
	if offset == blockSize {
		offset = 0
	}

	for len(decrypted) < unknownLength {
		blockStart := len(decrypted) + randomPrefixLength + offset
		blockEnd := blockStart + blockSize

		for i := blockSize - 1; i >= 0; i-- {
			bunchOfBs := bytes.Repeat([]byte("B"), i+offset)
			knownPrefix := append(bunchOfBs, decrypted...)
			lookup := GenerateByteLookupTable(oracle, knownPrefix, blockStart, blockEnd)

			cipher := oracle(bunchOfBs)
			block := cipher[blockStart:blockEnd]

			decrypted = append(decrypted, lookup[string(block)])
			if len(decrypted) == unknownLength {
				break
			}
		}
	}

	return decrypted, nil
}
