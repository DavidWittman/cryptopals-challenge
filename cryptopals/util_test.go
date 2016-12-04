package cryptopals

import (
	"bytes"
	"testing"
)

func TestSplitBytes(t *testing.T) {
	buf := []byte("aaaaabbbbbcccccdddddeeeeefffff")
	result := SplitBytes(buf, 5)
	expected := [][]byte{
		[]byte("aaaaa"),
		[]byte("bbbbb"),
		[]byte("ccccc"),
		[]byte("ddddd"),
		[]byte("eeeee"),
		[]byte("fffff"),
	}
	for i, b := range result {
		if !bytes.Equal(b, expected[i]) {
			t.Fatalf("Got bytes: %v, expected: %v", b, expected[i])
		}
	}
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
