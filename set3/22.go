/*
 * Crack an MT19937 seed
 *
 * Make sure your MT19937 accepts an integer seed value. Test it (verify that
 * you're getting the same sequence of outputs given a seed).
 *
 * Write a routine that performs the following operation:
 *
 *   - Wait a random number of seconds between, I don't know, 40 and 1000.
 *   - Seeds the RNG with the current Unix timestamp
 *   - Waits a random number of seconds again.
 *   - Returns the first 32 bit output of the RNG.
 *
 * You get the idea. Go get coffee while it runs. Or just simulate the passage
 * of time, although you're missing some of the fun of this exercise if you do
 * that.
 *
 * From the 32 bit RNG output, discover the seed.
 *
 */

package set_three

import (
	"math/rand"
	"time"
)

func sleepRand(min, max int) {
	var n int

	rand.Seed(time.Now().Unix())

	for n < min {
		n = rand.Intn(max)
	}

	time.Sleep(time.Second * time.Duration(n))
}

func GenerateRandomInt() uint32 {
	mt := NewMersenneTwister()

	sleepRand(40, 1000)
	mt.Seed(uint32(time.Now().Unix()))
	sleepRand(40, 300)

	return mt.Extract()
}

func FindSeed(r uint32) uint32 {
	var seed uint32
	// Check all timestamps for today (2016/12/21)
	var start, end uint32 = 1482300000, 1482386400

	mt := NewMersenneTwister()

	for i := start; i < end; i++ {
		mt.Seed(i)
		if mt.Extract() == r {
			seed = i
			break
		}
	}

	return seed
}
