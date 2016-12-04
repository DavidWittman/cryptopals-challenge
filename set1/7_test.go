package set_one

import (
	"testing"
)

func TestDecryptAES128ECB(t *testing.T) {
	t.Log(DecryptAESECBFile("./data/7.txt"))
}
