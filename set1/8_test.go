package set_one

import (
	"testing"
)

func TestFindECBLine(t *testing.T) {
	ecbLine := FindECBLine("./data/8.txt")
	if ecbLine == "" {
		t.Fatalf("Unable to detect ECB encrypted cipher")
	}
}
