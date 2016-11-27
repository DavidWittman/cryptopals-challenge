package set_two

import (
	"bytes"
	"testing"
)

func TestCoinflip(t *testing.T) {
	results := make(map[bool]int)
	for i := 0; i < 100000; i++ {
		results[coinflip()]++
	}
	t.Logf("Heads: %d, Tails: %d", results[true], results[false])
	// I should probably assert a minimum error here
}

func TestGenerateRandomBytes(t *testing.T) {
	// I know this test is stupid. I'm sorry.
	for i := 0; i < 1000; i++ {
		bytes1, _ := GenerateRandomBytes(16)
		bytes2, _ := GenerateRandomBytes(16)

		if bytes.Compare(bytes1, bytes2) == 0 {
			t.Errorf("Generated same bytes twice")
		}
	}
}

func TestRandomlyEncryptECBOrCBC(t *testing.T) {
	data := []byte("this is some plaintext.\nhere is some more plaintext.")
	_, mode, err := RandomlyEncryptECBOrCBC(data)
	if err != nil {
		t.Errorf("Failed to encrypt (%s): %s", mode, err)
	}
}

func TestDetectECBOrCBC(t *testing.T) {
	// The plaintext must have at least one identical block or it won't detect ECB
	data := bytes.Repeat([]byte("B"), 128)

	for i := 0; i < 100; i++ {
		result, mode, err := RandomlyEncryptECBOrCBC(data)
		if err != nil {
			t.Errorf("Failed to encrypt (%s): %s", mode, err)
		}
		if mode != DetectECBOrCBC(result, 16) {
			t.Errorf("Wrong block mode detected.")
		}
	}
}
