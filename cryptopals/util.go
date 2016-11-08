package cryptopals

import (
	"encoding/base64"
	"io/ioutil"
	"os"
)

func ReadAllBase64(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return []byte{}, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, file))
	if err != nil {
		return []byte{}, err
	}

	return bytes, nil
}
