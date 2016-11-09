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
