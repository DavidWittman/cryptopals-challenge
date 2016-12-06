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

func TestFindMatchingBlock(t *testing.T) {
	blockSize := 16

	type testCase struct {
		input    []byte
		expected int
	}
	var tests []testCase

	for i := 0; i < 100; i++ {
		prefix, _ := GenerateRandomBytes(i * blockSize)
		input := append(prefix, bytes.Repeat([]byte{1}, blockSize*2)...)
		tests = append(tests, testCase{input, i * blockSize})
	}

	for _, tt := range tests {
		result := FindMatchingBlock(tt.input, 16)
		if result != tt.expected {
			t.Errorf("FindMatchingBytes failed. Expected: %v, Got: %v", tt.expected, result)
		}
		if tt.input[result] != 1 {
			t.Errorf("First byte of matching block is not 1; may have incorrectly matched.")
		}
	}
}
