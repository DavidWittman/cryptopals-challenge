package set_three

import "testing"

func TestUndoRightShiftXOR(t *testing.T) {
	for _, tt := range []struct {
		y        uint32
		shift    uint32
		expected uint32
	}{
		{179, 3, 167},
		{875507, 5, 864864},
		{3499211612, 18, 3499200376},
		{8738642, 7, 8675309},
	} {
		result := undoRightShiftXOR(tt.y, tt.shift)
		if result != tt.expected {
			t.Errorf("undoRightShiftXOR failed. Got: %d, Expected: %d", result, tt.expected)
		}
	}

}

func TestUndoLeftShiftXOR(t *testing.T) {
	for _, tt := range []struct {
		y        uint32
		shift    uint32
		number   uint32
		expected uint32
	}{
		{3499200376, 15, 4022730752, 387288952},
		{8675181, 4, 420, 8675309},
		{6853670, 5, 5555, 6848678},
	} {
		result := undoLeftShiftXOR(tt.y, tt.shift, tt.number)
		if result != tt.expected {
			t.Errorf("undoLeftShiftXOR failed. Got: %d, Expected: %d", result, tt.expected)
		}
	}

}

func TestUntemper(t *testing.T) {
	for _, tt := range []struct {
		y        uint32
		expected uint32
	}{
		{3499211612, 2601187879},
		{3890346734, 2270374771},
		{3586334585, 3254473187},
		{545404204, 705526435},
		{581869302, 3919438689},
	} {
		result := untemper(tt.y)
		if result != tt.expected {
			t.Errorf("untemper failed: Got: %d, Expected: %d", result, tt.expected)
		}
	}
}

func TestCloneMersenneTwister(t *testing.T) {
	mt := NewMersenneTwister()
	mt.Seed(uint32(237462375))

	clone := CloneMersenneTwister(mt)

	for i := 0; i < len(mt.state); i++ {
		if j, k := mt.Extract(), clone.Extract(); j != k {
			t.Errorf("Clone failed. RNG: %d, Clone: %d", j, k)
		}
	}
}
