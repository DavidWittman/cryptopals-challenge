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

func TestGenerateByteLookupTable(t *testing.T) {
	result := GenerateByteLookupTable(Oracle, []byte("AAAAAAA"), 0, 8)
	t.Log(result)
	if len(result) != 256 {
		t.Error("Did not generate full dictionary from Oracle")
	}
}

func TestBreakECB(t *testing.T) {
	result := BreakECB(Oracle)
	//t.Log("BreakECB result: ", result)
	t.Logf("BreakECB result: %s", result)
}
