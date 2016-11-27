package cryptopals

import (
	"crypto/cipher"
)

// Go provides a CBC block mode, but there's no fun in using that

type cbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

type cbcDecrypter cbc
type cbcEncrypter cbc

func newCBC(b cipher.Block, iv []byte) *cbc {
	return &cbc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	}
}

func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcDecrypter)(newCBC(block, iv))
}

func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcEncrypter)(newCBC(block, iv))
}

func (x *cbcDecrypter) BlockSize() int { return x.blockSize }

func (x *cbcEncrypter) BlockSize() int { return x.blockSize }

func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		err := FixedXOR(dst[:x.blockSize], x.iv)
		if err != nil {
			panic(err)
		}
		// Use the ciphertext (from src) as the iv for the next block
		x.iv = src[:x.blockSize]
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func (x *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		err := FixedXOR(src[:x.blockSize], x.iv)
		if err != nil {
			panic(err)
		}
		x.b.Encrypt(dst, src[:x.blockSize])
		// use the ciphertext (from dst) as the iv for the next block
		x.iv = dst[:x.blockSize]
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
