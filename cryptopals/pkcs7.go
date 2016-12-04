package cryptopals

import (
	"bytes"
)

func PKCS7Pad(padLength int, block []byte) []byte {
	var result []byte

	if padLength <= 1 || padLength >= 256 {
		panic("9: bad pad length")
	}

	remainder := padLength - (len(block) % padLength)

	pad := []byte{byte(remainder)}

	// This syntax is strange here, but it expands the byte slice returned
	// from bytes.Repeat into individual byte arguments, as required by `append`.
	result = append(block, bytes.Repeat(pad, remainder)...)

	return result
}
