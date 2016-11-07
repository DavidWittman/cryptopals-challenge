package set_one

import (
	"bytes"
	"testing"
)

func TestFixedXOR(t *testing.T) {
	expected := []byte("746865206b696420646f6e277420706c6179")
	result, _ := FixedXOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	if !bytes.Equal(expected, result) {
		t.Errorf("Expected: %s Got: %s", expected, result)
	}
}
