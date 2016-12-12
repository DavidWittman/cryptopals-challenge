package cryptopals

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
)

// Go provides a CTR block mode, but there's no fun in using that

type ctr struct {
	b         cipher.Block
	blockSize int
	iv        int
	counter   int
}

func NewCTR(b cipher.Block, iv int) *ctr {
	return &ctr{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	}
}

func (x *ctr) BlockSize() int { return x.blockSize }

func (x *ctr) Nonce() []byte {
	iv := &bytes.Buffer{}
	counter := &bytes.Buffer{}

	binary.Write(iv, binary.LittleEndian, uint64(x.iv))
	binary.Write(counter, binary.LittleEndian, uint64(x.counter))

	return append(iv.Bytes(), counter.Bytes()...)
}

func (x *ctr) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	copy(dst, src)

	for len(src) > 0 {
		nonce := x.Nonce()
		encryptedNonce := make([]byte, x.blockSize)
		x.b.Encrypt(encryptedNonce, nonce)

		if len(src) < x.blockSize {
			err := FixedXOR(dst[:len(src)], encryptedNonce[:len(src)])
			if err != nil {
				panic(err)
			}
			// Empty src so the loop finishes
			src = []byte{}
		} else {
			err := FixedXOR(dst[:x.blockSize], encryptedNonce)
			if err != nil {
				panic(err)
			}

			src = src[x.blockSize:]
			dst = dst[x.blockSize:]
			x.counter += 1
		}
	}
}
