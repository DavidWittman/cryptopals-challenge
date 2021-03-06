package cryptopals

import (
	"bytes"
	"fmt"
)

func PKCS7Pad(padLength int, block []byte) []byte {
	if padLength <= 1 || padLength >= 256 {
		panic("9: bad pad length")
	}

	remainder := padLength - (len(block) % padLength)

	pad := []byte{byte(remainder)}

	// This syntax is strange here, but it expands the byte slice returned
	// from bytes.Repeat into individual byte arguments, as required by `append`.
	return append(block, bytes.Repeat(pad, remainder)...)
}

func PKCS7Unpad(data []byte) ([]byte, error) {
	if !IsPKCS7Padded(data) {
		return []byte{}, fmt.Errorf("Input is not PKCS7 padded")
	}

	padLength := int(data[len(data)-1])
	return data[:len(data)-padLength], nil
}

func IsPKCS7Padded(data []byte) bool {
	var pad []byte
	// Padding input will always result in an even length
	if len(data)%2 == 1 {
		return false
	}

	last := int(data[len(data)-1])
	if last == 0 || last > len(data) {
		return false
	}

	pad = data[len(data)-last:]

	return bytes.Compare(pad, bytes.Repeat([]byte{byte(last)}, last)) == 0
}

// Tries to PKCS7 unpad. If it fails, it just returns the original input
func MaybePKCS7Unpad(data []byte) []byte {
	unpadded, err := PKCS7Unpad(data)
	if err != nil {
		return data
	}
	return unpadded
}
