/*
 * CTR bitflipping
 *
 * There are people in the world that believe that CTR resists bit flipping
 * attacks of the kind to which CBC mode is susceptible.
 *
 * Re-implement the CBC bitflipping exercise from earlier to use CTR mode
 * instead of CBC mode. Inject an "admin=true" token.
 *
 */

package set_four

import (
	"fmt"
	"strings"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const iv = 0

// Quotes out semi-colons and equals signs
func sanitizeInput(input string) string {
	return strings.Replace(strings.Replace(input, ";", "\";\"", -1), "=", "\"=\"", -1)
}

func EncryptedComment(input string) []byte {
	input = sanitizeInput(input)
	plaintext := fmt.Sprintf("comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon", input)
	encrypted, err := cryptopals.AESCTR([]byte(plaintext), cryptopals.RANDOM_KEY, iv)
	if err != nil {
		panic(err)
	}
	return encrypted
}

func DecryptCommentAndCheckAdmin(input []byte) (bool, error) {
	adminString := ";admin=true;"
	decrypted, err := cryptopals.AESCTR(input, cryptopals.RANDOM_KEY, iv)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(decrypted), adminString), nil
}

// Inject `;admin=true;` into an encrypted comment and return the ciphertext
func BitflipInjectAdmin(ciphertext []byte) ([]byte, error) {
	inject := []byte(";admin=true;")
	// Arbitrarily inject at the 11th position in the ciphertext
	start := 11
	end := start + len(inject)
	knownPlaintext := []byte("oking%20MCs;")

	// XOR the known plaintext with the ciphertext to get the keystream value
	if err := cryptopals.FixedXOR(ciphertext[start:end], knownPlaintext); err != nil {
		return []byte{}, err
	}

	// Now XOR the keystream with the data we want to inject to encrypt it
	if err := cryptopals.FixedXOR(ciphertext[start:end], inject); err != nil {
		return []byte{}, err
	}

	return ciphertext, nil
}
