package set_two

import (
	"testing"
)

func Test10(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, len(key))
	result, err := DecryptFileCBC("./testdata/10.txt", key, iv)
	if err != nil {
		t.Errorf("Error decrypting: %s", err)
	}
	t.Logf("Decrypted text:\n\n%s", result)
}
