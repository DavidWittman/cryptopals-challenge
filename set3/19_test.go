package set_three

import (
	"bytes"
	"testing"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

func TestSplitDecodeAndEncrypt(t *testing.T) {
	results, err := splitDecodeAndEncrypt("./data/19.txt")

	if err != nil {
		t.Errorf("Error splitting bytes: %s", err)
	}

	if len(results) != 40 {
		t.Errorf("Wrong number of results returned from SplitDecodeAndEncrypt: %d", len(results))
	}
}

func TestGuessFixedNonceCTRKeystream(t *testing.T) {
	ciphers, err := splitDecodeAndEncrypt("./data/19.txt")
	if err != nil {
		t.Errorf("Error preparing input for BreakFixedNonceCTR: %s", err)
	}
	keystream := GuessFixedNonceCTRKeystream(ciphers)
	for _, cipher := range ciphers {
		err := cryptopals.FixedXOR(cipher, keystream[:len(cipher)])
		if err != nil {
			t.Errorf("Error XORing cipher: %s", err)
		}
		t.Log(string(cipher))
	}
}

func TestFindLongest(t *testing.T) {
	longest := []byte("zomg")
	input := [][]byte{
		[]byte("foo"),
		[]byte("bar"),
		[]byte("zomg"),
		[]byte(""),
		[]byte("1"),
		[]byte("fail"),
	}
	result := findLongest(input)
	if bytes.Compare(result, longest) != 0 {
		t.Errorf("Bad result: %s", result)
	}
}
