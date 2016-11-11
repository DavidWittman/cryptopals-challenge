/*

Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

```
"YELLOW SUBMARINE"
```

... padded to 20 bytes would be:

```
"YELLOW SUBMARINE\x04\x04\x04\x04"
```

*/

package set_two

import (
	"bytes"
)

func PKCS7Pad(padLength int, block []byte) []byte {
	var result []byte

	// Return the block if it's non-zero and already a multiple of the padLength
	if len(block) != 0 && len(block)%padLength == 0 {
		return block
	}

	remainder := padLength - (len(block) % padLength)

	pad := []byte{byte(remainder)}

	// This syntax is strange here, but it expands the byte slice returned
	// from bytes.Repeat into individual byte arguments, as required by `append`.
	result = append(block, bytes.Repeat(pad, remainder)...)

	return result
}
