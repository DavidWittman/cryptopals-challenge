package set_one

import (
	"testing"
)

func TestDecryptAES128ECB(t *testing.T) {
	t.Log(DecryptAESECBFile("./testdata/7.txt"))
}
