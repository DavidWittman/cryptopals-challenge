package set_two

import (
	"strings"
	"testing"
)

func TestStripMetachars(t *testing.T) {
	metachars := "&="
	tt := []string{
		"foo=bar&baz=42",
		"====foo====bar&baz===42",
		"====================",
		"&&&&&&&&&&&&&&",
		"=======&&&&&===&=&=&=",
		"======42&&&&&&bar+++",
	}

	for _, input := range tt {
		if result := stripMetachars(input); strings.ContainsAny(result, metachars) {
			t.Errorf("Meta characters not stripped: %s", result)
		}
	}
}

func TestProfileFor(t *testing.T) {
	expected := "email=foo@bar.com&uid=10&role=user"
	result := ProfileFor("foo@bar.com")
	if result != expected {
		t.Errorf("Profile incorrect: %s", result)
	}
	result = ProfileFor("fo=o@bar.c&om&")
	if result != expected {
		t.Errorf("Profile incorrect: %s", result)
	}
}
