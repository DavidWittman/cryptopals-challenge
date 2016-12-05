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
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

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

	randomPrefix, _ := cryptopals.GenerateRandomBytes(cryptopals.RandomInt(1, 255))

	data = append(randomPrefix, append(data, unknownBytes...)...)
	result, _ := cryptopals.EncryptAESECB(data, cryptopals.RANDOM_KEY)
	return result
}

// Determine the unknown suffix within oracle by passing it 2 repeating blocks
// and running the oracle until we find our matching blocks in the ciphertext.
// Then we know that our input landed on a boundary and we can determine the
// length of the unknown input.
func DetermineUnknownStringSize(oracle EncryptionOracle, blockSize int) int {
	cipher := EncryptUntilMatchingBlocks(oracle, []byte{}, blockSize)

	// This gives us the start of our input block. Determine the size of the unknown
	// string by chopping off our input string and the random bytes at the front of the cipher
	index := cryptopals.FindMatchingBlock(cipher, blockSize)
	unknownSize := len(cipher[index+(blockSize*2):])
	return unknownSize
}

// Generate ciphers from oracle until we find one with a matching block
func EncryptUntilMatchingBlocks(oracle EncryptionOracle, input []byte, blockSize int) []byte {
	// Make sure it's actually ECB
	if !IsOracleEBC(oracle, blockSize) {
		panic("Provided Oracle is not ECB")
	}

	// Add two identical blocks so we can locate our prefix
	ecbTest := bytes.Repeat([]byte{0x01}, blockSize*2)
	input = append(ecbTest, input...)

	for {
		cipher := oracle(input)
		// It's important to find ADJACENT matching blocks, otherwise we
		// could potentially match blocks with values we're seeding in to
		// the Oracle to brute force the unknown text
		if cryptopals.FindAdjacentMatchingBlocks(cipher, blockSize) != -1 {
			return cipher
		}
	}
}

// Just like GenerateByteLookupTable fom ch12, but tests ECB
func GenerateHarderLookupTable(oracle EncryptionOracle, prefix []byte, blockStart, blockEnd int) map[string]byte {
	var i byte

	result := make(map[string]byte)

	blockSize := blockEnd - blockStart
	if blockSize < 1 {
		panic("Invalid block size")
	}

	for i = 0; i < 128; i++ {
		input := append(prefix, i)

		cipher := EncryptUntilMatchingBlocks(oracle, input, blockSize)
		index := cryptopals.FindMatchingBlock(cipher, blockSize)

		// Skip over our matching block and the short block offset
		start := index + (blockSize * 2) + blockStart
		end := start + blockSize
		shortBlock := cipher[start:end]

		result[string(shortBlock)] = i
	}

	return result
}

func BreakHarderECBOracle(oracle EncryptionOracle) ([]byte, error) {
	var decrypted []byte

	// TODO(dw): Should be detecting this
	blockSize := 16
	unknownLength := DetermineUnknownStringSize(oracle, blockSize)

	for len(decrypted) < unknownLength {
		blockStart := len(decrypted)
		blockEnd := blockStart + blockSize

		for i := blockSize - 1; i >= 0; i-- {
			bunchOfBs := bytes.Repeat([]byte("B"), i)
			knownPrefix := append(bunchOfBs, decrypted...)
			lookup := GenerateHarderLookupTable(oracle, knownPrefix, blockStart, blockEnd)

			// TODO(dW): Can modify this function to just return everything after the matching blocks
			cipher := EncryptUntilMatchingBlocks(oracle, bunchOfBs, blockSize)
			index := cryptopals.FindMatchingBlock(cipher, blockSize)

			// Skip over matching block and the short block offset
			start := index + (blockSize * 2) + blockStart
			end := start + blockSize
			block := cipher[start:end]

			decrypted = append(decrypted, lookup[string(block)])

			if lookup[string(block)] == 0 {
				return decrypted, nil
			}
			fmt.Println(string(decrypted), len(decrypted))
		}
	}

	return cryptopals.PKCS7Unpad(decrypted), nil
}
