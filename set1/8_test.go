package set_one

import (
	"testing"
)

func TestFindECBLine(t *testing.T) {
	ecbLine := FindECBLine("./testdata/8.txt")
	if ecbLine == "" {
		t.Fatalf("Unable to detect ECB encrypted cipher")
	}
}
