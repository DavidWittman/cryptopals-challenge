package set_two

import (
	"testing"
)

func TestOracle(t *testing.T) {
	_, err := Oracle([]byte("foo"))
	if err != nil {
		t.Error(err)
	}
}
