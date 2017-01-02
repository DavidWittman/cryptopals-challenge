package set_four

import (
	"bytes"
	"testing"
)

func TestMD4Pad(t *testing.T) {
	// From https://www.whitehatsec.com/blog/hash-length-extension-attacks/
	message := []byte("xxxxxxxxxxxreport.pdf")
	expected := []byte{
		0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x72, 0x65,
		0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x64, 0x66, 0x80, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	result := MD4Pad(message)

	if bytes.Compare(result, expected) != 0 {
		t.Errorf("\nExpected:\t%x\nGot:\t\t%x", expected, result)
	}
}

func TestValidateSecretPrefixMD4(t *testing.T) {
	for _, tt := range []struct {
		message  []byte
		mac      string
		expected bool
	}{
		// Generated with `echo -ne "\x00\x01Super Secret Prefix\x02\x03this is the message" | openssl dgst -md4`
		{[]byte("this is the message"), "1d619696c6c671c1b2085cc6867900ba", true},
		{[]byte("this is the message"), "c37c7b5326ce400d23d9807b13f1ea39", false},
	} {
		result := ValidateSecretPrefixMD4(tt.message, tt.mac)
		if result != tt.expected {
			t.Errorf("MD4 MAC Validation failed.\nMessage:\t%v\nMAC:\t\t%v", tt.message, tt.mac)
		}
	}
}

func TestGetMD4Registers(t *testing.T) {
	expected := [4]uint32{2526437661, 3245459142, 3327920306, 3120593286}
	result := GetMD4Registers("1d619696c6c671c1b2085cc6867900ba")
	for i := 0; i < len(result); i++ {
		if result[i] != expected[i] {
			t.Fatalf("Expected: %v, Got: %v", expected, result)
		}
	}
}

func TestMD4LengthExtension(t *testing.T) {
	// This is from TestValidateSecretPrefixMD4
	inMAC := "1d619696c6c671c1b2085cc6867900ba"
	// echo -en "\x00\x01Super Secret Prefix\x02\x03this is the message\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x01\x00\x00\x00\x00\x00\x00attack!" | openssl dgst -md4
	expectedMAC := "3a72fae95e4efcd693b90a2f49f7f1e8"

	inMessage := []byte("this is the message")
	extension := []byte("attack!")

	mac, _ := MD4LengthExtension(inMAC, inMessage, extension, ValidateSecretPrefixMD4)

	if mac != expectedMAC {
		t.Errorf("Extension failed. Got: %s Expected: %s", mac, expectedMAC)
	}
}

func TestChallenge30(t *testing.T) {
	attack := ";admin=true"
	mac, message := Challenge30()

	if !ValidateSecretPrefixMD4(message, mac) {
		t.Fatalf("Length extension attack for challenge 30 failed to validate")
	}

	start := len(message) - len(attack)
	if string(message[start:]) != attack {
		t.Errorf("%s was not successfully added to authenticated message.", attack)
	}
}
