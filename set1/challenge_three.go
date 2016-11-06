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
	"encoding/hex"
	"strings"
)

// scoreText will value the contents of a string based on the frequency of
// common English characters defined in the array goodChars.
// Higher scores are better, and a string with no matching characters will
// return 0.
func scoreText(s string) int {
	score := 0
	goodChars := [12]string{"a", "e", "i", "o", "u", "r", "s", "t", "l", "m", "n", " "}

	for i := range goodChars {
		score += strings.Count(strings.ToLower(s), goodChars[i])
	}

	return score
}

// getXORFunction returns a function which XORs a rune with the provided rune
func getXORFunction(i rune) func(rune) rune {
	return func(char rune) rune {
		return char ^ i
	}
}

func DecryptXOR(enc string) string {
	highScore := 0
	var decrypted string

	encBytes, err := hex.DecodeString(enc)
	if err != nil {
		panic(err)
	}

	for i := 0; i < 256; i++ {
		plaintext := strings.Map(getXORFunction(rune(i)), string(encBytes))
		score := scoreText(plaintext)
		if score > highScore {
			decrypted = plaintext
			highScore = score
		}
	}

	return decrypted
}
