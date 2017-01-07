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
	"net/http"
	"strings"
	"time"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

// Sleep for this many milliseconds while comparing the signature
// The challenge suggests 50ms, but that makes our tests really slow
const COMPARE_DELAY = 20

// The HTTP server will listen on this address:port
const LISTEN_ADDR = ":8771"

type timedResponse struct {
	r       *http.Response
	id      string
	elapsed int64
}

// Start the validation server for challenge 31 and 32
func StartServer() {
	http.HandleFunc("/test", ValidationServer)
	http.HandleFunc("/test32", FasterValidationServer)
	go http.ListenAndServe(LISTEN_ADDR, nil)
}

func ValidationServer(w http.ResponseWriter, req *http.Request) {
	status := 500

	message := req.FormValue("file")
	sig := req.FormValue("signature")

	if InsecureValidateHMAC(message, sig) {
		status = 200
	}

	http.Error(w, http.StatusText(status), status)
}

func InsecureValidateHMAC(message, signature string) bool {
	goodSig := SHA256HMAC(cryptopals.RANDOM_KEY, []byte(message))
	return InsecureCompare([]byte(signature), []byte(goodSig), COMPARE_DELAY)
}

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

// Iterates over a map of bytes and returns the key with the longest value
func findSlowestRequest(requests map[string]int64) string {
	slowest := int64(0)
	slowestKey := ""

	for key, value := range requests {
		if value > slowest {
			slowest = value
			slowestKey = key
		}
	}

	return slowestKey
}

// Exploits a comparison timing attack in url
// `url` is the full path to the http endpoint to attack against. The guesses
// will be appended to this string. Ex. "localhost:8771/test?file=foo&signature="
// Endpoint is expected to return 200 when the signature successfully validates
// Returns an empty string if no result is found
func ExploitTimingAttack(url string, length int) string {
	var known string
	results := make(chan timedResponse)

	// These are the characters we're brute-forcing
	chars := "0123456789abcdef"

	for i := 0; i < length; i++ {
		requests := make(map[string]int64)
		// Fill in the rest of the signature with a character that won't match
		filler := strings.Repeat("_", length-(i+1))

		for j := 0; j < len(chars); j++ {
			signature := strings.Join([]string{known, string(chars[j]), filler}, "")
			urlWithSig := strings.Join([]string{url, signature}, "")
			go TimeHTTPRequest(urlWithSig, string(chars[j]), results)
		}

		// Collect results
		for j := 0; j < len(chars); j++ {
			res := <-results
			// Return the result if the server returns a 200
			if res.r.StatusCode == http.StatusOK {
				return strings.Join([]string{known, res.id}, "")
			}
			requests[res.id] = res.elapsed
		}

		bestGuess := findSlowestRequest(requests)
		known = strings.Join([]string{known, bestGuess}, "")
	}

	return ""
}

// Times an HTTP request to `url` and passes a timedResponse
// object to the results channel upon completion.
// In this challenge, the `id` used to identify the request is just
// the character we're attempting in this iteration.
func TimeHTTPRequest(url, id string, results chan timedResponse) {
	start := time.Now()
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	results <- timedResponse{resp, id, time.Since(start).Nanoseconds()}
}
