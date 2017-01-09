package set_four

import "testing"

// This test is depdendent on 31_test.go, which starts the HTTP server
// It's jank but I'm being lazy

func TestExploitMoreDifficultTimingAttack(t *testing.T) {
	// This works, but it takes forever, so skip it
	t.Skip()

	// SHA1 = 20 bytes = 40 hex chars
	result := ExploitMoreDifficultTimingAttack("http://localhost:8771/test32?file=foo&signature=", 40)
	if result == "" {
		t.Errorf("No result received from timing attack")
	}
}
