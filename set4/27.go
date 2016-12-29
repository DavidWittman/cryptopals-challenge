/*
 * Recover the key from CBC with IV=Key
 *
 * Take your code from the CBC exercise (16) and modify it so that it
 * repurposes the key for CBC encryption as the IV.
 *
 * Applications sometimes use the key as an IV on the auspices that both the
 * sender and the receiver have to know the key already, and can save some
 * space by using it as both a key and an IV.
 *
 * Using the key as an IV is insecure; an attacker that can modify ciphertext
 * in flight can get the receiver to decrypt a value that will reveal the key.
 *
 * The CBC code from exercise 16 encrypts a URL string. Verify each byte of the
 * plaintext for ASCII compliance (ie, look for high-ASCII values).
 * Noncompliant messages should raise an exception or return an error that
 * includes the decrypted plaintext (this happens all the time in real systems,
 * for what it's worth).
 *
 * Use your code to encrypt a message that is at least 3 blocks long:
 *
 *     AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
 *
 * Modify the message (you are now the attacker):
 *
 *     C_1, C_2, C_3 -> C_1, 0, C_1
 *
 * Decrypt the message (you are now the receiver) and raise the appropriate
 * error if high-ASCII is found.
 *
 * As the attacker, recovering the plaintext from the error, extract the key:
 *
 *     P'_1 XOR P'_3
 *
 */

package set_four

import (
	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

type InvalidASCIIError struct {
	msg string
}

func (e InvalidASCIIError) Error() string {
	return e.msg
}

// Returns false if any values in input are invalid ASCII (>127)
func validASCII(input []byte) bool {
	for i := 0; i < len(input); i++ {
		if input[i] > 127 {
			return false
		}
	}
	return true
}

// Validates that plaintext is valid ASCII and then encrypts with CBC
// using the same value for the key and IV
// If the ASCII is invalid, an error is returned along with the original plaintext.
func ValidateAndEncrypt(plaintext []byte) ([]byte, error) {
	if !validASCII(plaintext) {
		return plaintext, InvalidASCIIError{"Plaintext contains invalid ASCII characters"}
	}
	encrypted, err := cryptopals.EncryptAESCBC(plaintext, cryptopals.RANDOM_KEY, cryptopals.RANDOM_KEY)
	if err != nil {
		return []byte{}, err
	}
	return encrypted, nil
}

func DecryptAndValidate(cipher []byte) ([]byte, error) {
	decrypted, err := cryptopals.DecryptAESCBC(cipher, cryptopals.RANDOM_KEY, cryptopals.RANDOM_KEY)
	if err != nil {
		return []byte{}, err
	}
	decrypted = cryptopals.MaybePKCS7Unpad(decrypted)
	return decrypted, nil
}
