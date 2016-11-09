/*
Challenge Six

There's a file here. It's been base64'd after being encrypted with repeating-key XOR. Decrypt it.

Here's how:

 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
this is a test
and
wokka wokka!!!
is 37. Make sure your code agrees before you proceed.
 2. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
 3. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
 4. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
 5. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
 6. Solve each block as if it was single-character XOR. You already have code to do this.
 7. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
*/

package set_one

import (
	"bytes"
	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const MAX_KEYSIZE = 40

// Count the number of 1 bits in byte b
// We're passing in a byte from the XORed byte-array here to determine the hamming distance
func countBits(b byte) int {
	var count int
	for ; b > 0; b >>= 1 {
		count += int(b & 1)
	}
	return count
}

// Transpose a slice of byte slices. e.g. AA,BB,CC == ABC,ABC
func transpose(chunks [][]byte) [][]byte {
	result := make([][]byte, len(chunks[0]))
	for _, chunk := range chunks {
		for j, b := range chunk {
			result[j] = append(result[j], b)
		}
	}
	return result
}

// The Hamming Distance (or edit distance) is the number of differing bits between two buffers
// This is computed by XORing the two buffers and adding up the bits in the resultant buffer.
func HammingDistance(s1, s2 []byte) int {
	var distance int
	for i, c := range s1 {
		distance += countBits(s2[i] ^ c)
	}
	return distance
}

// Computes the hamming distance of `size` sized blocks in cipher
// Distances are normalized and averaged
func BlockDistance(cipher []byte, size int) float64 {
	var distance float64

	// Don't continue if there are fewer than four blocks to compare
	if len(cipher) < (size * 4) {
		return -1
	}

	// Minus one because we're looking ahead a block to compare
	iters := (len(cipher) / size) - 1

	for i := 0; i < iters; i++ {
		a := cipher[i*size : (i+1)*size]
		b := cipher[(i+1)*size : (i+2)*size]
		distance += float64(HammingDistance(a, b))
	}

	// Normalize and average distance
	return distance / float64(size) / float64(iters)
}

// Attempts to guess the Vigenere cipher key size by comparing the edit distance of blocks
// within cipher. The guessed keysize with the lowest edit distance is selected.
// Attempts key sizes between 2 and 64 bytes.
func GuessKeySize(cipher []byte) int {
	bestKeySize := 0
	bestDistance := 9999999.99

	for i := 2; i <= MAX_KEYSIZE; i++ {
		distance := BlockDistance(cipher, i)
		if distance >= 0 && distance < bestDistance {
			bestDistance = distance
			bestKeySize = i
		}
	}

	return bestKeySize
}

// This function will open `filename` and attempt to break a Vigenere (repeating-key XOR) cipher,
// returning the key as a slice of bytes
func BreakRepeatingKeyXOR(filename string) []byte {
	cipherBytes, err := cryptopals.ReadAllBase64(filename)
	if err != nil {
		panic(err)
	}
	keySize := GuessKeySize(cipherBytes)

	byteGroups := transpose(cryptopals.SplitBytes(cipherBytes, keySize))
	for i, byteGroup := range byteGroups {
		byteGroups[i] = DecryptXOR(byteGroup)
	}

	decrypted := bytes.Join(transpose(byteGroups), []byte{})

	return decrypted
}
