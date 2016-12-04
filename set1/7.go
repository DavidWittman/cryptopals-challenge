package set_one

/*
AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
*/

import (
	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

const KEY = "YELLOW SUBMARINE"

func DecryptAESECBFile(filename string) string {
	contents, err := cryptopals.ReadAllBase64(filename)
	if err != nil {
		panic(err)
	}

	decrypted, _ := cryptopals.DecryptAESECB([]byte(contents), []byte(KEY))
	return string(decrypted)
}
