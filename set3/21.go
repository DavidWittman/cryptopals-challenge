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
 * The coefficients for MT19937-64 are:[46]
 *
 *     (w, n, m, r) = (64, 312, 156, 31)
 *     a = 0xB5026F5AA96619E9
 *     f = 6364136223846793005
 *     (u, d) = (29, 0x5555555555555555)
 *     (s, b) = (17, 0x71D67FFFEDA60000)
 *     (t, c) = (37, 0xFFF7EEE000000000)
 *     l = 43
 *
 */

package set_three

const (
	w uint64 = 64
	n uint64 = 312
	m uint64 = 156
	r uint64 = 31

	a uint64 = 0xB5026F5AA96619E9

	f uint64 = 6364136223846793005
	u uint64 = 29
	d uint64 = 0x5555555555555555

	s uint64 = 17
	b uint64 = 0x71D67FFFEDA60000

	t uint64 = 37
	c uint64 = 0xFFF7EEE000000000

	l uint64 = 43

	lowerMask uint64 = (1 << r)
	upperMask uint64 = ^lowerMask & 0xFFFFFFFF
)

type mersenneTwister struct {
	index uint64
	state [n]uint64
}

func NewMersenneTwister(seed uint64) *mersenneTwister {
	mt := &mersenneTwister{}
	mt.index = n
	mt.state[0] = seed

	for i := uint64(1); i < n; i++ {
		mt.state[i] = (f*(mt.state[i-1]^(mt.state[i-1]>>w-2)) + i)
	}

	return mt
}

func (mt *mersenneTwister) Twist() {
	for i := uint64(0); i < n-1; i++ {
		x := (mt.state[i] & upperMask) + ((mt.state[i+1] % n) & lowerMask)
		xA := x >> 1
		if x%2 == 1 {
			// Uneven; lowest bit of x is 1
			xA = xA ^ a
		}
		mt.state[i] = mt.state[(i+m)%n] ^ xA
	}
	mt.index = 0
}

// Extract returns a random uint64
func (mt *mersenneTwister) Extract() uint64 {
	if mt.index >= n {
		if mt.index > n {
			panic("mersenneTwister: Generator was never seeded")
		}
		mt.Twist()
	}

	y := mt.state[mt.index]
	y ^= ((y >> u) & d)
	y ^= ((y << s) & b)
	y ^= ((y << t) & c)
	y ^= (y >> l)

	mt.index++

	return y
}
