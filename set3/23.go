/*
 * Clone an MT19937 RNG from its output
 *
 * The internal state of MT19937 consists of 624 32 bit integers.
 *
 * For each batch of 624 outputs, MT permutes that internal state. By permuting
 * state regularly, MT19937 achieves a period of 2**19937, which is Big.
 *
 * Each time MT19937 is tapped, an element of its internal state is subjected
 * to a tempering function that diffuses bits through the result.
 *
 * The tempering function is invertible; you can write an "untemper" function
 * that takes an MT19937 output and transforms it back into the corresponding
 * element of the MT19937 state array.
 *
 * To invert the temper transform, apply the inverse of each of the operations
 * in the temper transform in reverse order. There are two kinds of operations
 * in the temper transform each applied twice; one is an XOR against a
 * right-shifted value, and the other is an XOR against a left-shifted value
 * AND'd with a magic number. So you'll need code to invert the "right" and the
 * "left" operation.
 *
 * Once you have "untemper" working, create a new MT19937 generator, tap it for
 * 624 outputs, untemper each of them to recreate the state of the generator,
 * and splice that state into a new instance of the MT19937 generator.
 *
 * The new "spliced" generator should predict the values of the original.
 *
 * Stop and think for a second.
 * How would you modify MT19937 to make this attack hard? What would happen if
 * you subjected each tempered output to a cryptographic hash?
 *
 */

package set_three

// Takes a value y, and applies the inverse of y ^= (y >> shift)
// This effectively reapplies the XOR operations to all bytes except the top
// shift bytes. We know those are the original bytes because X ^ 0 = X.
func undoRightShiftXOR(y, shift uint32) uint32 {
	var mask uint32 = ((1 << shift) - 1) << (32 - shift)

	// This is a ghetto ceil operation. We want to run ceil(32/shift) times to
	// mask all the bits in y.
	n := (32 + shift - 1) / shift
	for i := uint32(0); i < n; i++ {
		y ^= (y >> shift) & mask
		mask >>= shift
	}

	return y
}

// Applies the inverse of y ^= (y << shift) & number
func undoLeftShiftXOR(y, shift, number uint32) uint32 {
	var mask uint32 = (1 << shift) - 1

	// Ghetto ceil
	n := (32 + shift - 1) / shift

	for i := uint32(0); i < n; i++ {
		y ^= (y << shift) & mask & number
		mask <<= shift
	}

	return y
}

// Untempers a random value extracted from an MT19937 RNG to find the state for
// that particular iteration
func untemper(y uint32) uint32 {
	// These constants (l, t, c, etc.) are defined in 21.go

	y = undoRightShiftXOR(y, l)
	y = undoLeftShiftXOR(y, t, c)
	y = undoLeftShiftXOR(y, s, b)
	y = undoRightShiftXOR(y, u)

	return y
}

func CloneMersenneTwister(mt *mersenneTwister) *mersenneTwister {
	clone := NewMersenneTwister()

	for i := uint32(0); i < n; i++ {
		clone.state[i] = untemper(mt.Extract())
	}

	clone.index = mt.index

	return clone
}
