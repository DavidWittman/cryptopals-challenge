package set_one

import (
	"testing"
)

func TestFindXORedStringInFile(t *testing.T) {
	result, _ := FindXORedStringInFile("data/4.txt")
	if result == "" {
		t.Fail()
	}
	t.Log("Decrypted text:", result)
}
