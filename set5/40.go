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

package set_five

import "crypto/rsa"

type KeyAndCipher struct {
	Key    *rsa.PublicKey
	Cipher []byte
}

func CRT(data [3]KeyAndCipher) *big.Int {
	result := big.NewInt(1)
	N = new(big.Int).Mul(data[0].N, data[1].N)
	N.Mul(data[2].N)

	result.Mul(result, new(big.Int).SetBytes(keys[0].Cipher))
	result.Mul(result, new(big.Int).Div(N, keys[0].N))
	result.Mul(result, new(big.Int).ModInverse(new(big.Int).Div(N, keys[0].N), keys[0].N))

	result1 := big.NewInt(1)
	result1.Mul(result1, new(big.Int).SetBytes(keys[1].Cipher))
	result1.Mul(result1, new(big.Int).Div(N, keys[1].N))
	result1.Mul(result1, new(big.Int).ModInverse(new(big.Int).Div(N, keys[1].N), keys[0].N))

	result2 := big.NewInt(1)
	result2.Mul(result2, new(big.Int).SetBytes(keys[2].Cipher))
	result2.Mul(result2, new(big.Int).Div(N, keys[2].N))
	result2.Mul(result2, new(big.Int).ModInverse(new(big.Int).Div(N, keys[2].N), keys[0].N))

	result.Add(result, result1)
	result.Add(result, result2)

	return result.Mod(result, N)
}

func BroadcastRSA(plaintext []byte) [3]KeyAndCipher {
	var result [3]KeyAndCipher

	for i := 0; i < 3; i++ {
		key, err := RSAGenerate()
		if err != nil {
			panic(err)
		}
		result[i] = KeyAndCipher{
			Key:    key.PublicKey,
			Cipher: RSAEncrypt(plaintext, key.PublicKey),
		}
	}

	return result
}
