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

func TestDetermineBlockSize(t *testing.T) {
	blockSize := DetermineBlockSize(Oracle)
	t.Log("Determined block size of", blockSize)
	if blockSize == 0 {
		t.Error("Unable to determine block size")
	}
}

func TestIsOracleEBC(t *testing.T) {
	if IsOracleEBC(Oracle, 16) != true {
		t.Error("IsOracleEBC did not correctly identify an EBC Oracle")
	}
}
