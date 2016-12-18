package cryptopals

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"time"
)

// A random 128 bit key, populated on package import in the init function below
var RANDOM_KEY []byte

func init() {
	var err error
	// Seed RNG
	rand.Seed(time.Now().Unix())

	// Generate random 128-bit key
	RANDOM_KEY, err = GenerateRandomBytes(16)
	if err != nil {
		panic(err)
	}
}

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

func ReadBase64String(input string) (string, error) {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(input))
	decoded, err := ioutil.ReadAll(decoder)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
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
	return rand.Intn(max-min) + min
}

// Generates `n` random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	result := make([]byte, n)
	_, err := rand.Read(result)
	if err != nil {
		return []byte{}, err
	}
	return result, nil
}

// Finds a matching block of size `size` in `data`
// Returns the index of the first matching block, -1 if not found
func FindMatchingBlock(data []byte, size int) int {
	chunks := SplitBytes(data, size)

	for i, chunkA := range chunks {
		for j, chunkB := range chunks {
			if i != j && bytes.Equal(chunkA, chunkB) {
				return i * size
			}
		}
	}

	return -1
}

// Transpose a slice of byte slices. e.g. AA,BB,CC == ABC,ABC
func TransposeBytes(chunks [][]byte) [][]byte {
	result := make([][]byte, len(chunks[0]))
	for _, chunk := range chunks {
		for j, b := range chunk {
			result[j] = append(result[j], b)
		}
	}
	return result
}
