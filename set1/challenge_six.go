/*
There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
this is a test
and
wokka wokka!!!
is 37. Make sure your code agrees before you proceed.
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
Solve each block as if it was single-character XOR. You already have code to do this.
For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.
*/

package set_one

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const MAX_KEYSIZE = 64

// Count the number of 1 bits in byte b
// We're passing in a byte from the XORed byte-array here to determine the hamming distance
func countBits(b byte) int {
	var count int
	for ; b > 0; b >>= 1 {
		count += int(b & 1)
	}
	return count
}

func hammingDistance(s1, s2 []byte) int {
	var distance int
	for i, c := range s1 {
		distance += countBits(s2[i] ^ c)
	}
	return distance
}

// Attempts to guess the Vigenere cipher key size by comparing the edit distance of blocks
// within cipher. The guessed keysize with the lowest edit distance is selected.
// Attempts key sizes between 2 and 64 bytes.
// Returns 0 on error.
func GuessKeySize(cipher []byte) uint8 {
	var keySize uint8
	distances := make(map[int]float64)

	for i := 2; i <= MAX_KEYSIZE; i++ {
		cipherReader := bytes.NewReader(cipher)
		block1 := make([]byte, i)
		block2 := make([]byte, i)

		for {
			n, err := cipherReader.Read(block1)
			if err == io.EOF {
				break
			} else if err != nil {
				panic(err)
			}

			n, err = cipherReader.Read(block2)
			if err == io.EOF {
				distances[i] += float64(hammingDistance(block1[:n], block2[:n]) / i)
				break
			} else if err != nil {
				panic(err)
			}

			distances[i] += float64(hammingDistance(block1, block2) / i)
		}
	}

	bestDistance := 999999.99
	for key, distance := range distances {
		if distance < bestDistance {
			bestDistance = distance
			keySize = uint8(key)
		}
	}

	return keySize
}

// This function will open `filename` and attempt to break a Vigenere (repeating-key XOR) cipher,
// returning the key as a slice of bytes
func BreakRepeatingKeyXOR(filename string) []byte {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	cipherBytes, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, file))
	if err != nil {
		panic(err)
	}
	keySize := GuessKeySize(cipherBytes)
	fmt.Println(keySize)

	return []byte{}
}
