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

// Generate specific bytes of the keystream
// Returns `length` bytes at `offset` from the keystream
func (x *ctr) KeystreamBytes(offset, length int) []byte {
	var result bytes.Buffer
	// Save and restore the original counter
	// This isn't thread safe but idgaf
	currCounter := x.counter
	defer func() {
		x.counter = currCounter
	}()

	if offset < 0 || length < 1 {
		panic("ctr.KeyStreamRange: offset must be >= 0 and length must be >= 1")
	}

	x.counter = offset / x.blockSize

	// Generate 1 more block than the length to make sure we have enough
	// bytes to trim off afterwards.
	for result.Len() < (length + x.BlockSize()) {
		nonce := x.Nonce()
		encryptedNonce := make([]byte, x.blockSize)
		x.b.Encrypt(encryptedNonce, nonce)
		result.Write(encryptedNonce)
		x.counter++
	}

	// Trim keystream
	start := offset % x.blockSize
	end := start + length

	return result.Bytes()[start:end]
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
