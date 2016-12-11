/*
 *
 * CBC bitflipping attacks
 *
 * Generate a random AES key.
 *
 * Combine your padding code and CBC code to write two functions.
 *
 * The first function should take an arbitrary input string, prepend the string:
 *
 *     "comment1=cooking%20MCs;userdata="
 *
 * .. and append the string:
 *
 *     ";comment2=%20like%20a%20pound%20of%20bacon"
 * The function should quote out the ";" and "=" characters.
 *
 * The function should then pad out the input to the 16-byte AES block length
 * and encrypt it under the random AES key.
 *
 * The second function should decrypt the string and look for the characters
 * ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert
 * each resulting string into 2-tuples, and look for the "admin" tuple).
 *
 * Return true or false based on whether the string exists.
 *
 * If you've written the first function properly, it should not be possible to
 * provide user input to it that will generate the string the second function is
 * looking for. We'll have to break the crypto to do that.
 *
 * Instead, modify the ciphertext (without knowledge of the AES key) to
 * accomplish this.
 *
 * You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
 * block:
 *
 *   - Completely scrambles the block the error occurs in
 *   - Produces the identical 1-bit error(/edit) in the next ciphertext block.
 *
 * Stop and think for a second.
 * Before you implement this attack, answer this question: why does CBC mode
 * have this property?
 *
 */

package set_two

import (
	"fmt"
	"strings"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

var iv []byte = []byte("YELLOW SUBMARINE")

// Quotes out semi-colons and equals signs
func sanitizeInput(input string) string {
	return strings.Replace(strings.Replace(input, ";", "\";\"", -1), "=", "\"=\"", -1)
}

func EncryptedComment(input string) []byte {
	input = sanitizeInput(input)
	plaintext := fmt.Sprintf("comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon", input)
	encrypted, err := cryptopals.EncryptAESCBC([]byte(plaintext), cryptopals.RANDOM_KEY, iv)
	if err != nil {
		panic(err)
	}
	return encrypted
}

func DecryptCommentAndCheckAdmin(input []byte) (bool, error) {
	adminString := ";admin=true;"
	decrypted, err := cryptopals.DecryptAESCBC(input, cryptopals.RANDOM_KEY, iv)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(decrypted), adminString), nil
}

// Inject `;admin=true;` into an encrypted comment and return the ciphertext
//
// To decrypt CBC, the ciphertext of the first block is XORed against the
// decrypted second block to produce the plaintext.
//
// E2 = Encrypted second block
// C1 = Ciphertext of 1st block
// P2 = Plaintext of second block
//
// P2 = E2 ^ C1
//
// Since we know P2 and C1, we can XOR those together to find E2.
//
// E2 = P2 ^ C1
//
// Then we just XOR the encrypted second block (E2) with the block we wish to
// inject as C1'.
//
// C1' = Modified ciphertext block; this XORs with E2 to inject our block
//
// C1' = E2 ^ []byte(";admin=true;lol=")
//
// Then, when decrypting, C1' is XORed against E2 to generate our string:
//
// C1' ^ E2 = ";admin=true;lol="
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
