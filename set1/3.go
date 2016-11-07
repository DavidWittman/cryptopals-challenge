/*
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext.
Character frequency is a good metric. Evaluate each output and choose the one with the best score.
*/

package set_one

import (
	"bytes"
	"encoding/hex"
	"strings"
)

// ScoreText will value the contents of a string based on the frequency of
// common English characters defined in the array goodChars.
// Higher scores are better, and a string with no matching characters will
// return 0.
func ScoreText(s string) int {
	score := 0
	goodChars := [12]string{"a", "e", "i", "o", "u", "r", "s", "t", "l", "m", "n", " "}

	for i := range goodChars {
		score += strings.Count(strings.ToLower(s), goodChars[i])
	}

	return score
}

// getXORFunction returns a function which XORs a byte with the provided byte
func getXORFunction(i rune) func(rune) rune {
	return func(char rune) rune {
		return char ^ i
	}
}

func DecryptHexStringXOR(enc string) string {
	encBytes, err := hex.DecodeString(enc)
	if err != nil {
		panic(err)
	}
	return string(DecryptXOR(encBytes))
}

func DecryptXOR(buf []byte) []byte {
	highScore := 0
	var decrypted []byte

	for i := 0; i < 256; i++ {
		plaintext := bytes.Map(getXORFunction(rune(i)), buf)
		score := ScoreText(string(plaintext))
		if score > highScore {
			decrypted = plaintext
			highScore = score
		}
	}

	return decrypted
}
