/*
Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
*/

package set_one

import (
	"encoding/hex"
	"errors"
)

func FixedXOR(buf1, buf2 string) ([]byte, error) {
	if len(buf1) != len(buf2) {
		return []byte{}, errors.New("Input buffer lengths not equal")
	}

	var result = make([]byte, len(buf1))

	buf1Bytes, err := hex.DecodeString(buf1)
	if err != nil {
		return []byte{}, err
	}

	buf2Bytes, err := hex.DecodeString(buf2)
	if err != nil {
		return []byte{}, err
	}

	for i := range buf1Bytes {
		buf2Bytes[i] ^= buf1Bytes[i]
	}

	hex.Encode(result, buf2Bytes)
	return result, nil
}
