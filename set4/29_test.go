package set_four

import (
	"bytes"
	"testing"
)

func TestSHA1Pad(t *testing.T) {
	// From https://www.whitehatsec.com/blog/hash-length-extension-attacks/
	message := []byte("xxxxxxxxxxxreport.pdf")
	expected := []byte{
		0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x64, 0x66, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8,
	}
	result := SHA1Pad(message)

	if bytes.Compare(result, expected) != 0 {
		t.Errorf("\nExpected:\t%x\nGot:\t\t%x", expected, result)
	}
}

func TestGetSHA1Registers(t *testing.T) {
	expected := [5]uint32{1167626098, 877034388, 3823716676, 885616355, 1620938639}
	result := GetSHA1Registers("45988f7234467b94e3e9494434c96ee3609d8f8f")
	for i := 0; i < len(result); i++ {
		if result[i] != expected[i] {
			t.Fatalf("Expected: %v, Got: %v", expected, result)
		}
	}
}

func TestSHA1LengthExtension(t *testing.T) {
	inMAC := "a0585899eaf1586b0596944c04c8959a87d34473"
	// echo -en "\x00\x01Super Secret Prefix\x02\x03this is the message\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x50attack!" | sha1sum
	expectedMAC := "79d974968572788102d4fef09e5cab517395821a"

	inMessage := []byte("this is the message")
	extension := []byte("attack!")

	mac, _ := SHA1LengthExtension(inMAC, inMessage, extension, ValidateSecretPrefixSHA1)

	if mac != expectedMAC {
		t.Errorf("Extension failed. Got: %s Expected: %s", mac, expectedMAC)
	}
}
