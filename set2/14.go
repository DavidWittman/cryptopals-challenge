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
	var cipher []byte

	input := bytes.Repeat([]byte("A"), blockSize*2)

	for cipher = oracle(input); cryptopals.FindMatchingBlock(cipher, blockSize) == -1; cipher = oracle(input) {
	}

	// This gives us the start of our input block. Determine the size of the unknown
	// string by chopping off our input string and the random bytes at the front of the cipher
	index := cryptopals.FindMatchingBlock(cipher, blockSize)
	unknownSize := len(cipher[index+len(input):])
	return unknownSize
}

func BreakHarderOracle(oracle EncryptionOracle) ([]byte, error) {
	// This is a little flawed; the block size detection will fail some small
	// percentage of the time because the random pad will cause fluctuations
	// in the length of the ciphertext.
	blockSize := DetermineBlockSize(oracle)
	blockSize += 1

	// This attack works by finding our payload in the output from the Oracle
	// and then stripping out everything before it.
	// Our attack payload should be at least 3 blocks long
	return []byte{}, nil
}
