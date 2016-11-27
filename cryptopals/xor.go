package cryptopals

import (
	"errors"
)

// Modified from Challenge 2

func FixedXOR(buf1, buf2 []byte) error {
	if len(buf1) != len(buf2) {
		return errors.New("Input buffer lengths not equal")
	}

	for i := range buf1 {
		buf1[i] ^= buf2[i]
	}

	return nil
}
