package set_one

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"
)

func TestCountBits(t *testing.T) {
	if countBits(byte(0x8F)) != 5 {
		t.Fail()
	}
	if countBits(byte(0x00)) != 0 {
		t.Fail()
	}
	if countBits(byte(0xFF)) != 8 {
		t.Fail()
	}
}

func TestHammingDistance(t *testing.T) {
	if HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")) != 37 {
		t.Fail()
	}
}

func TestGuessKeySize(t *testing.T) {
	file, err := os.Open("./data/6.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	cipherBytes, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, file))
	if err != nil {
		panic(err)
	}
	keySize := GuessKeySize(cipherBytes)

	if keySize != 29 {
		t.Fatalf("Incorrect key size. Expected: %v, got: %v", 29, keySize)
	}
}

func TestBreakRepeatingKeyXOR(t *testing.T) {
	t.Log(string(BreakRepeatingKeyXOR("./data/6.txt")))
}

func TestTranspose(t *testing.T) {
	chunks := [][]byte{
		[]byte("aa0aa"),
		[]byte("bbbb5"),
		[]byte("ccc4c"),
		[]byte("dd3dd"),
		[]byte("e2eee"),
		[]byte("1ffff"),
	}
	expected := [][]byte{
		[]byte("abcde1"),
		[]byte("abcd2f"),
		[]byte("0bc3ef"),
		[]byte("ab4def"),
		[]byte("a5cdef"),
	}
	result := transpose(chunks)
	for i, b := range result {
		if !bytes.Equal(b, expected[i]) {
			t.Fatalf("Got bytes: %v, expected: %v", b, expected[i])
		}
	}

	// Transpose again and make sure it's the same as when we begun
	doubleTranspose := transpose(result)
	for i, b := range doubleTranspose {
		if !bytes.Equal(b, chunks[i]) {
			t.Fatalf("Got bytes: %v, expected: %v", b, expected[i])
		}
	}

}
