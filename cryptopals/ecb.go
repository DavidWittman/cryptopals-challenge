package cryptopals

import (
	"crypto/cipher"
)

// From https://codereview.appspot.com/7860047

type ecb struct {
	b         cipher.Block
	blockSize int
}

type ecbDecrypter ecb
type ecbEncrypter ecb

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
