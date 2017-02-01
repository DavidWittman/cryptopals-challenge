package set_one

import (
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
	file, err := os.Open("./testdata/6.txt")
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
	t.Log(string(BreakRepeatingKeyXOR("./testdata/6.txt")))
}
