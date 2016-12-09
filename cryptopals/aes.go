package cryptopals

import (
	"crypto/aes"
)

func DecryptAESECB(cipher, key []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return []byte{}, err
	}

	blockMode := NewECBDecrypter(block)
	decrypted := make([]byte, len(cipher))
	blockMode.CryptBlocks(decrypted, cipher)

	return MaybePKCS7Unpad(decrypted), nil
}

func EncryptAESCBC(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	data = PKCS7Pad(len(key), data)
	blockMode := NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	blockMode.CryptBlocks(encrypted, data)

	return encrypted, nil
}

func EncryptAESECB(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	data = PKCS7Pad(len(key), data)
	blockMode := NewECBEncrypter(block)
	encrypted := make([]byte, len(data))
	blockMode.CryptBlocks(encrypted, data)

	return encrypted, nil
}
