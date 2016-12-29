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
	"bytes"

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

// Validates that plaintext is valid ASCII and then encrypts with CBC using the
// same random value for the key and IV.
// If the ASCII is invalid, an InvalidASCIIError is returned along with the
// original plaintext.
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

// Decrypts a cipher using the same random value for key and IV
// If the decrypted plaintext is invalid, an InvalidASCIIError is returned.
func DecryptAndValidate(cipher []byte) ([]byte, error) {
	plaintext, err := cryptopals.DecryptAESCBC(cipher, cryptopals.RANDOM_KEY, cryptopals.RANDOM_KEY)
	if err != nil {
		return []byte{}, err
	}
	if !validASCII(plaintext) {
		return plaintext, InvalidASCIIError{"Decrypted plaintext contains invalid ASCII characters"}
	}

	plaintext = cryptopals.MaybePKCS7Unpad(plaintext)
	return plaintext, nil
}

// Generate plaintext, encrypt, and feed it to our attack code
func Challenge27() ([]byte, error) {
	cipher, err := ValidateAndEncrypt(bytes.Repeat([]byte("YELLOW SUBMARINE"), 3))
	if err != nil {
		return []byte{}, err
	}
	return ExtractKey(cipher), nil
}

// Given a ciphertext at least three blocks in length, extract the key.
// The reason this works is because during decryption, CBC will use the cipher
// of the second block (which we're injecting as all 0s) and XOR that against
// the third block, which we have injected to be the same as the first block.
// So effectively we have P1 which is the actual decrypted first block, and
// P'1 which is P1 before being XORed with the IV (or key). XORing these
// values together reveals the key.
func ExtractKey(cipher []byte) []byte {
	var attackCipher bytes.Buffer

	blockSize := 16
	if len(cipher) < (blockSize * 3) {
		panic("Cipher must be at least 3 blocks long")
	}

	// C1 || 0 * blockSize || C1
	attackCipher.Write(cipher[:blockSize])
	attackCipher.Write(bytes.Repeat([]byte{0}, blockSize))
	attackCipher.Write(cipher[:blockSize])

	output, err := DecryptAndValidate(attackCipher.Bytes())
	if err != nil {
		// Ignore the Invalid ASCII errors. TBH I'm not even sure why
		// I even went through the trouble of raising these errors
		if _, ok := err.(InvalidASCIIError); !ok {
			panic(err)
		}
	}

	// KEY = P'1 ^ P'3
	err = cryptopals.FixedXOR(output[:blockSize], output[blockSize*2:blockSize*3])
	if err != nil {
		panic(err)
	}

	return output[:blockSize]
}
