/*
 * Break an MD4 keyed MAC using length extension
 *
 * Second verse, same as the first, but use MD4 instead of SHA-1. Having done
 * this attack once against SHA-1, the MD4 variant should take much less time;
 * mostly just the time you'll spend Googling for an implementation of MD4.
 *
 * You're thinking, why did we bother with this?
 * Blame Stripe. In their second CTF game, the second-to-last challenge involved
 * breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code was floating
 * all over the Internet. MD4 code, not so much.
 */

package set_four

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
	"github.com/DavidWittman/cryptopals-challenge/cryptopals/md4"
)

func ValidateSecretPrefixMD4(message []byte, mac string) bool {
	md := md4.New()
	md.Write(SecretPrefix)
	md.Write(message)
	h := md.Sum(nil)
	return hex.EncodeToString(h) == mac
}

// Adapted from golang.org/x/crypto/md4/md4.go
// The only difference between this pad and SHA1PAd is that the 64-bit length
// appended to the end of the pad is little-endian.
func MD4Pad(message []byte) []byte {
	var result bytes.Buffer
	result.Write(message)

	length := len(message)

	// Padding.  Add a 1 bit and 0 bits until len(result) % 64 == 56
	// This allows us add a 8 byte integer to the end and align with the 64-byte block size
	var tmp [64]byte
	tmp[0] = 0x80
	if length%64 < 56 {
		result.Write(tmp[0 : 56-length%64])
	} else {
		result.Write(tmp[0 : 64+56-length%64])
	}

	// Length in bits.
	length <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(length >> (8 * i))
	}
	result.Write(tmp[0:8])

	return result.Bytes()
}

// Extract the 4 registers from a MD4 sum
func GetMD4Registers(mac string) [4]uint32 {
	var states [4]uint32

	hashBytes, err := hex.DecodeString(mac)
	if err != nil {
		panic(err)
	}
	// Split into 32-bit registers
	registers := cryptopals.SplitBytes(hashBytes, 4)

	if len(registers) != 4 {
		panic("Invalid MD4 hash length")
	}

	for i := 0; i < len(registers); i++ {
		states[i] = binary.LittleEndian.Uint32(registers[i])
	}

	return states
}

// Performs an MD4 length extension on the provided mac and message.
// The attack bytes are appended to the message (with padding) and and the resulting
// message and valid MAC are returned.
func MD4LengthExtension(mac string, message, attack []byte, validate ValidationFunction) (string, []byte) {
	// Maximum length for the secret prefix
	maxLength := 256

	registers := GetMD4Registers(mac)

	for i := 1; i <= maxLength; i++ {
		// Make a prefix of length i and just take the message and pad from it
		messageWithPad := MD4Pad(append(bytes.Repeat([]byte("A"), i), message...))[i:]
		length := uint64(len(messageWithPad) + i)

		// Clone the state of the known-good MD4 by passing in the extracted
		// registers and guessed length of (secret + messageWithPad)
		md := md4.NewExtension(registers, length)
		md.Write(attack)
		newMAC := hex.EncodeToString(md.Sum(nil))

		newMessage := append(messageWithPad, attack...)

		if validate(newMessage, newMAC) {
			return newMAC, newMessage
		}
	}

	return "", []byte{}
}

func Challenge30() (string, []byte) {
	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	knownMAC := "c2a0604e87f68ea8760ddf26fed720a8"
	attack := []byte(";admin=true")

	return MD4LengthExtension(knownMAC, message, attack, ValidateSecretPrefixMD4)
}
