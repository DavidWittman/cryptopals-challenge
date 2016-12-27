/*
 * Break "random access read/write" AES CTR
 *
 * Back to CTR. Encrypt the recovered plaintext from this file (the ECB
 * exercise) under CTR with a random key (for this exercise the key should be
 * unknown to you, but hold on to it).
 *
 * Now, write the code that allows you to "seek" into the ciphertext, decrypt,
 * and re-encrypt with different plaintext. Expose this as a function, like,
 * "edit(ciphertext, key, offset, newtext)".
 *
 * Imagine the "edit" function was exposed to attackers by means of an API call
 * that didn't reveal the key or the original plaintext; the attacker has the
 * ciphertext and controls the offset and "new text".
 *
 * Recover the original plaintext.
 *
 * Food for thought.
 *
 * A folkloric supposed benefit of CTR mode is the ability to easily "seek
 * forward" into the ciphertext; to access byte N of the ciphertext, all you
 * need to be able to do is generate byte N of the keystream. Imagine if you'd
 * relied on that advice to, say, encrypt a disk.
 *
 */

package set_four

import (
	"bytes"
	"crypto/aes"
	"io/ioutil"
	"os"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func encryptFileCTR(filename string, key []byte, iv int) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return []byte{}, err
	}
	defer file.Close()

	plaintext, err := ioutil.ReadAll(file)
	if err != nil {
		return []byte{}, err
	}

	return cryptopals.AESCTR(plaintext, key, iv)
}

func Edit(cipher, key []byte, offset int, newText []byte) []byte {
	var result []byte

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ctr := cryptopals.NewCTR(block, 0)
	keystream := ctr.KeystreamBytes(offset, len(newText))

	newCipher := make([]byte, len(newText))
	copy(newCipher, newText)

	err = cryptopals.FixedXOR(newCipher, keystream)
	if err != nil {
		panic(err)
	}

	result = append(result, cipher[:offset]...)
	result = append(result, newCipher...)

	if len(result) < len(cipher) {
		result = append(result, cipher[len(result):]...)
	}

	return result
}

func EditAPI(cipher []byte, offset int, newText []byte) []byte {
	return Edit(cipher, cryptopals.RANDOM_KEY, offset, newText)
}

func RecoverPlaintext(cipher []byte) []byte {
	keystream := EditAPI(cipher, 0, bytes.Repeat([]byte{0}, len(cipher)))
	plaintext := make([]byte, len(cipher))
	copy(plaintext, cipher)
	err := cryptopals.FixedXOR(plaintext, keystream)
	if err != nil {
		panic(err)
	}
	return plaintext
}
