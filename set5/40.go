/*
 * Implement an E=3 RSA Broadcast attack
 *
 * Assume you're a Javascript programmer. That is, you're using a naive
 * handrolled RSA to encrypt without padding.
 *
 * Assume you can be coerced into encrypting the same plaintext three times,
 * under three different public keys. You can; it's happened.
 *
 * Then an attacker can trivially decrypt your message, by:
 *
 *  1. Capturing any 3 of the ciphertexts and their corresponding pubkeys
 *  2. Using the CRT to solve for the number represented by the three
 *     ciphertexts (which are residues mod their respective pubkeys)
 *  3. Taking the cube root of the resulting number
 *
 * The CRT says you can take any number and represent it as the combination of a
 * series of residues mod a series of moduli. In the three-residue case, you
 * have:
 *
 *     result =
 *       (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
 *       (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
 *       (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
 *
 * where:
 *
 *      c_0, c_1, c_2 are the three respective residues mod
 *      n_0, n_1, n_2
 *
 *      m_s_n (for n in 0, 1, 2) are the product of the moduli
 *      EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
 *
 *      N_012 is the product of all three moduli
 *
 * To decrypt RSA using a simple cube root, leave off the final modulus
 * operation; just take the raw accumulated result and cube-root it.
 *
 */

/*
 * Notes:
 *  - n values are just the modulus portion of the public key
 *  - c_0, c_1, and c_2 are just the ciphertexts, i don't know why they are
 *    referred to as "residues mod [their respective n]"
 */

package set_five

import (
	"crypto/rsa"
	"math/big"
)

type KeyAndCipher struct {
	Key    *rsa.PublicKey
	Cipher []byte
}

func CRTAttack(keys [3]KeyAndCipher) []byte {
	result := big.NewInt(0)

	N := new(big.Int).Mul(keys[0].Key.N, keys[1].Key.N)
	N.Mul(N, keys[2].Key.N)

	for _, key := range keys {
		product := big.NewInt(1)
		product.Mul(product, new(big.Int).SetBytes(key.Cipher))
		product.Mul(product, new(big.Int).Div(N, key.Key.N))
		product.Mul(product, new(big.Int).ModInverse(new(big.Int).Div(N, key.Key.N), key.Key.N))
		result.Add(result, product)
	}

	return cubeRoot(result.Mod(result, N)).Bytes()
}

func BroadcastRSA(plaintext []byte) [3]KeyAndCipher {
	var result [3]KeyAndCipher

	for i := 0; i < 3; i++ {
		key, err := RSAGenerate()
		if err != nil {
			panic(err)
		}
		result[i] = KeyAndCipher{
			Key:    &key.PublicKey,
			Cipher: RSAEncrypt(plaintext, &key.PublicKey),
		}
	}

	return result
}

// Thanks Filippo!
func cubeRoot(cube *big.Int) *big.Int {
	var big3 = big.NewInt(3)

	x := new(big.Int).Rsh(cube, uint(cube.BitLen())/3*2)
	if x.Sign() == 0 {
		panic("can't start from 0")
	}
	for {
		d := new(big.Int).Exp(x, big3, nil)
		d.Sub(d, cube)
		d.Div(d, big3)
		d.Div(d, x)
		d.Div(d, x)
		if d.Sign() == 0 {
			break
		}
		x.Sub(x, d)
	}
	for new(big.Int).Exp(x, big3, nil).Cmp(cube) < 0 {
		x.Add(x, big1)
	}
	for new(big.Int).Exp(x, big3, nil).Cmp(cube) > 0 {
		x.Sub(x, big1)
	}
	// Return the cube, rounded down.
	// if new(big.Int).Exp(x, big3, nil).Cmp(cube) != 0 {
	// 	panic("not a cube")
	// }
	return x
}
