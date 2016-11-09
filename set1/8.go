/*
Detect AES in ECB mode

In this file are a bunch of hex-encoded ciphertexts.
One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

*/

package set_one

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
	"os"
)

func FindECBLine(filename string) string {
	var _ string

	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		cipher, err := hex.DecodeString(scanner.Text())
		if err != nil {
			panic(err)
		}

		chunks := cryptopals.SplitBytes(cipher, 16)

		for i, chunkA := range chunks {
			for j, chunkB := range chunks {
				if i != j && bytes.Equal(chunkA, chunkB) {
					return string(cipher)
				}
			}
		}

	}

	return ""
}
