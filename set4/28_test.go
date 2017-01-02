package set_four

import "testing"

func TestValidateSecretPrefixSHA1(t *testing.T) {
	for _, tt := range []struct {
		message  []byte
		mac      string
		expected bool
	}{
		// Generated with `echo -ne "\x00\x01Super Secret Prefix\x02\x03this is the message" | sha1sum`
		{[]byte("this is the message"), "a0585899eaf1586b0596944c04c8959a87d34473", true},
		{[]byte("this is the message"), "c37c7b5326ce400d23d9807b13f1ea396861a0b5", false},
	} {
		result := ValidateSecretPrefixSHA1(tt.message, tt.mac)
		if result != tt.expected {
			t.Errorf("SHA-1 MAC Validation failed.\nMessage:\t%v\nMAC:\t\t%v", tt.message, tt.mac)
		}
	}
}

func TestTamperMessage(t *testing.T) {
	message := []byte("this is the message")
	mac := "a0585899eaf1586b0596944c04c8959a87d34473"
	if err := TamperMessage(message, mac); err != nil {
		t.Error(err)
	}
}

func TestRandomBytesDontMatch(t *testing.T) {
	mac := "a0585899eaf1586b0596944c04c8959a87d34473"
	iterations := 1000
	if err := RandomBytesDontMatch(mac, iterations); err != nil {
		t.Error(err)
	}
}
