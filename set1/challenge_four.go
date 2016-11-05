/*
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
*/

package set_one

import (
	"bufio"
	"os"
)

func FindXORedStringInFile(filename string) (string, error) {
	var result string
	highScore := 0

	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		plaintext := DecryptXOR(scanner.Text())
		score := scoreText(plaintext)
		if score > highScore {
			highScore = score
			result = plaintext
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return result, nil
}
