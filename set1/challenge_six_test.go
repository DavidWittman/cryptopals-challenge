package set_one

import (
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
	if hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")) != 37 {
		t.Fail()
	}
}

func TestGuessKeySize(t *testing.T) {
	testBytes := []byte{0, 1, 23, 4, 5, 6, 7, 1, 2, 4, 5, 6, 3, 3, 6, 7}
	keySize := GuessKeySize(testBytes)
	t.Log("Keysize: ", keySize)
}

func TestBreakRepeatingKeyXOR(t *testing.T) {
	t.Log(BreakRepeatingKeyXOR("./data/6.txt"))
}
