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

func DecryptAESCBC(cipher, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return []byte{}, err
	}

	blockMode := NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(cipher))
	blockMode.CryptBlocks(decrypted, cipher)

	return decrypted, nil
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

func AESCTR(data, key []byte, iv int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	blockMode := NewCTR(block, iv)
	result := make([]byte, len(data))
	blockMode.CryptBlocks(result, data)

	return result, nil
}
