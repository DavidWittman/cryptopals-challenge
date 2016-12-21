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

func GenerateRandomInt() uint32 {
	var n int

	// We're not seeding this so it will always generate the same value, but meh
	for n < 40 {
		n = rand.Intn(1000)
	}

	time.Sleep(time.Second * time.Duration(n))

	mt := NewMersenneTwister()
	mt.Seed(uint32(time.Now().Unix()))

	return mt.Extract()
}
