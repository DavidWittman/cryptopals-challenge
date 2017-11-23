package set_five

import (
	"testing"
)

func TestGenerateRSA(t *testing.T) {
	key, err := GenerateRSA()
	if err != nil {
		t.Error(err)
	}
	t.Logf("%+v", key)
}
