package set_two

import (
	"testing"
)

func TestOracle(t *testing.T) {
	result := Oracle([]byte("foo"))
	if len(result) == 0 {
		t.Error("Oracle returned nothing!")
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

func TestGenerateByteLookupTable(t *testing.T) {
	result := GenerateByteLookupTable(Oracle, []byte("AAAAAAA"), 0, 8)
	if len(result) != 128 {
		t.Error("Did not generate full dictionary from Oracle")
	}
}

func TestBreakECB(t *testing.T) {
	result := BreakECB(Oracle)
	t.Logf("BreakECB result:\n%s", result)
}
