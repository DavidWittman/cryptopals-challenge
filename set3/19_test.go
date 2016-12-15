package set_three

import (
	"bytes"
	"testing"
)

func TestSplitAndDecode(t *testing.T) {
	input := `Z28gbmluamEgZ28gbmluamEgZ28=
SSBncmFiYmVkIG15IG5pbmUsIGFsbCBJIGhlYXJkIHdhcyBzaGVsbHM=
SWYgdGhlcmUgd2FzIGEgcHJvYmxlbSwgeW8sIEknbGwgc29sdmUgaXQ=`

	expected := [][]byte{
		[]byte("go ninja go ninja go"),
		[]byte("I grabbed my nine, all I heard was shells"),
		[]byte("If there was a problem, yo, I'll solve it"),
	}

	results, err := splitAndDecode(input)

	if err != nil {
		t.Errorf("Error splitting bytes: %s", err)
	}

	if len(results) == 0 {
		t.Errorf("No results returned from splitAndDecode")
	}

	for i, result := range results {
		if bytes.Compare(result, expected[i]) != 0 {
			t.Errorf("Split and decode failed. Expected: %s, Got: %s", expected[i], result)
		}
	}
}
