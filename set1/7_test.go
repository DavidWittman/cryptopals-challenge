package set_one

import (
	"testing"
)

func TestDecryptAES128ECB(t *testing.T) {
	t.Log(DecryptAES128ECB("./data/7.txt"))
}
