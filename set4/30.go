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
	"fmt"

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
		states[i] = binary.BigEndian.Uint32(registers[i])
	}

	return states
}

// Performs an MD4 length extension on the provided mac and message.
// The attack bytes are appended to the message (with padding) and and the resulting
// message and valid MAC are returned.
func MD4LengthExtension(mac string, message, attack []byte, validate ValidationFunction) (string, []byte) {
	// Maximum length for the secret prefix
	// TODO(dw): Reset to 256
	maxLength := 23

	registers := GetMD4Registers(mac)

	for i := 1; i <= maxLength; i++ {
		// Make a prefix of length i and just take the message and pad from it
		messageWithPad := MDPad(append(bytes.Repeat([]byte("A"), i), message...))[i:]
		length := uint64(len(messageWithPad) + i)

		// Clone the state of the known-good MD4 by passing in the extracted
		// registers and guessed length of (secret + messageWithPad)
		md := md4.NewExtension(registers, length)
		md.Write(attack)
		newMAC := hex.EncodeToString(md.Sum(nil))
		fmt.Println(length, messageWithPad)

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
