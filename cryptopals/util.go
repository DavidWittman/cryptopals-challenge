package cryptopals

import (
	"encoding/base64"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
)

func ReadAllBase64(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return []byte{}, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, file))
	if err != nil {
		return []byte{}, err
	}

	return bytes, nil
}

// Splits a byte slice into length chunks
func SplitBytes(buf []byte, length int) [][]byte {
	chunks := [][]byte{}
	for offset := 0; offset < len(buf); offset += length {
		if offset+length >= len(buf) {
			chunks = append(chunks, buf[offset:])
		} else {
			chunks = append(chunks, buf[offset:offset+length])
		}
	}
	return chunks
}

// Returns a non-cryptographically secure random number between
// `min` and `max` (inclusive)
func RandomInt(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}
