/*
 * Implement and break HMAC-SHA1 with an artificial timing leak
 *
 * The psuedocode on Wikipedia should be enough. HMAC is very easy.
 *
 * Using the web framework of your choosing (Sinatra, web.py, whatever), write
 * a tiny application that has a URL that takes a "file" argument and a
 * "signature" argument, like so:
 *
 *     http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e
 *     5d63fdc88efb51
 *
 * Have the server generate an HMAC key, and then verify that the "signature" on
 * incoming requests is valid for "file", using the "==" operator to compare the
 * valid MAC for a file with the "signature" parameter (in other words, verify
 * the HMAC the way any normal programmer would verify it).
 *
 * Write a function, call it "insecure_compare", that implements the ==
 * operation by doing byte-at-a-time comparisons with early exit (ie, return
 * false at the first non-matching byte).
 *
 * In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each
 * byte).
 *
 * Use your "insecure_compare" function to verify the HMACs on incoming
 * requests, and test that the whole contraption works. Return a 500 if the MAC
 * is invalid, and a 200 if it's OK.
 *
 * Using the timing leak in this application, write a program that discovers the
 * valid MAC for any file.
 *
 * Why artificial delays?
 *
 * Early-exit string compares are probably the most common source of
 * cryptographic timing leaks, but they aren't especially easy to exploit. In
 * fact, many timing leaks (for instance, any in C, C++, Ruby, or Python)
 * probably aren't exploitable over a wide-area network at all. To play with
 * attacking real-world timing leaks, you have to start writing low-level timing
 * code. We're keeping things cryptographic in these challenges.
 */

package set_four

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

func SHA256HMAC(key, message []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}

// Insecurely implements == by doing a byte-at-a-time comparison of a and b
// It is insecure because there is a timing leak, which is controlled by
// the parameter `delay`, which sets the number of milliseconds to sleep
// after comparing each byte.
// Returns false immediately if the lengths do not match
func InsecureCompare(a, b []byte, delay uint8) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		time.Sleep(time.Duration(delay) * time.Millisecond)
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
