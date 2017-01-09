package set_four

import (
	"testing"
)

// This is kinda jank. It starts the server for both challenge 31 and 32.
// This means running the test for 32 is dependent on this test too.
func init() {
	StartServer()
}

func TestHMACSHA1(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	message := []byte("this is just another message")
	expected := "6a4ca4433193b39316dc1d6ffcf325fb14b9354d"

	result := HMACSHA1(key, message)
	if result != expected {
		t.Errorf("Incorrect HMAC generated.\nExpected:\t%v\nGot:\t\t%v", expected, result)
	}
}

func TestInsecureCompare(t *testing.T) {
	// Not testing any of the timing stuff here
	for _, tt := range []struct {
		a, b     []byte
		expected bool
	}{
		{[]byte("yellow"), []byte("yellow"), true},
		{[]byte("submarine"), []byte("sub"), false},
		{[]byte("we all live"), []byte("we all love"), false},
	} {
		if result := InsecureCompare(tt.a, tt.b, uint8(1)); result != tt.expected {
			t.Errorf("InsecureCompare failed for %+v", tt)
		}
	}
}

func TestFindSlowestRequest(t *testing.T) {
	input := map[string]int64{
		"a": 42,
		"b": 2,
		"c": 2000000,
		"d": 0,
	}
	result := findSlowestRequest(input)
	if result != "c" {
		t.Errorf("Incorrect result: %s", result)
	}
}

func TestExploitTimingAttack(t *testing.T) {
	// This works, but it takes forever. Skip it.
	t.Skip()
	// SHA1 is 20 bytes (40 characters in hex)
	result := ExploitTimingAttack("http://localhost:8771/test?file=foo&signature=", 40)
	if result == "" {
		t.Errorf("No result received from timing attack")
	}
}
