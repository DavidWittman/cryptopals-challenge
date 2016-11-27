package set_two

import (
	"bytes"
	"testing"
)

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
