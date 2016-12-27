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
// TODO(dw): Make this work for CTR
func BitflipInjectAdmin(ciphertext []byte) ([]byte, error) {
	blockSize := 16
	inject := []byte(";admin=true;lol=")
	secondBlock := []byte("%20MCs;userdata=")

	// XOR the plaintext of the second block with the ciphertext of the first
	// block to determine the encrypted value without the CBC XOR
	if err := cryptopals.FixedXOR(secondBlock, ciphertext[:blockSize]); err != nil {
		return []byte{}, err
	}

	// XOR the encrypted block with the injected admin block to find out what we
	// should set our ciphertext block to.
	if err := cryptopals.FixedXOR(inject, secondBlock); err != nil {
		return []byte{}, err
	}

	return append(inject, ciphertext[blockSize:]...), nil
}
