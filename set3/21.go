/*
 * Implement the MT19937 Mersenne Twister RNG
 *
 * You can get the psuedocode for this from Wikipedia.
 *
 * If you're writing in Python, Ruby, or (gah) PHP, your language is probably
 * already giving you MT19937 as "rand()"; don't use rand(). Write the RNG
 * yourself.
 *
 * NOTES:
 *
 * The coefficients for MT19937 are:
 *
 *     (w, n, m, r) = (32, 624, 397, 31)
 *     a = 0x9908B0DF
 *     f = 1812433253
 *     (u, d) = (11, 0xFFFFFFFF)
 *     (s, b) = (7, 0x9D2C5680)
 *     (t, c) = (15, 0xEFC60000)
 *     l = 18
 *
 */

package set_three

const (
	w uint32 = 32
	n uint32 = 624
	m uint32 = 397
	r uint32 = 31

	a uint32 = 0x9908B0DF
	f uint32 = 1812433253

	u uint32 = 11
	d uint32 = 0xFFFFFFFF

	s uint32 = 7
	b uint32 = 0x9D2C5680

	t uint32 = 15
	c uint32 = 0xEFC60000

	l uint32 = 18

	lowerMask uint32 = 0x7FFFFFFF
	upperMask uint32 = 0x80000000

	// Default seed value if none is provided
	DEFAULT_SEED uint32 = 5489
)

type mersenneTwister struct {
	index uint32
	state [n]uint32
}

func NewMersenneTwister() *mersenneTwister {
	return &mersenneTwister{index: n + 1}
}

func (mt *mersenneTwister) Seed(seed uint32) {
	mt.index = n
	mt.state[0] = seed

	for i := uint32(1); i < n; i++ {
		mt.state[i] = (f*(mt.state[i-1]^(mt.state[i-1]>>(w-2))) + i)
	}
}

func (mt *mersenneTwister) twist() {
	for i := uint32(0); i < n; i++ {
		x := (mt.state[i] & upperMask) + (mt.state[(i+1)%n] & lowerMask)
		xA := x >> 1
		if x%2 == 1 {
			// Uneven; lowest bit of x is 1
			xA ^= a
		}
		mt.state[i] = mt.state[(i+m)%n] ^ xA
	}

	mt.index = 0
}

// Extract returns a random uint32
func (mt *mersenneTwister) Extract() uint32 {
	if mt.index >= n {
		if mt.index > n {
			mt.Seed(DEFAULT_SEED)
		}
		mt.twist()
	}

	y := mt.state[mt.index]
	// The & d here is effectively a noop because d = 0xFFFFFFFF
	y ^= (y >> u) & d
	y ^= (y << s) & b
	y ^= (y << t) & c
	y ^= (y >> l)

	mt.index++

	return y
}
