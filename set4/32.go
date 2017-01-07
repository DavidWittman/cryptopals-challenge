/*
 * Break HMAC-SHA1 with a slightly less artificial timing leak
 *
 * Reduce the sleep in your "insecure_compare" until your previous solution
 * breaks. (Try 5ms to start.)
 *
 * Now break it again.
 */

package set_four

import (
	"net/http"
	"strings"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

// Sleep for this many milliseconds while comparing the signature
const FASTER_COMPARE_DELAY = 5

func FasterValidationServer(w http.ResponseWriter, req *http.Request) {
	status := 500

	message := req.FormValue("file")
	sig := req.FormValue("signature")

	if FasterInsecureValidateHMAC(message, sig) {
		status = 200
	}

	http.Error(w, http.StatusText(status), status)
}

func FasterInsecureValidateHMAC(message, signature string) bool {
	goodSig := SHA256HMAC(cryptopals.RANDOM_KEY, []byte(message))
	return InsecureCompare([]byte(signature), []byte(goodSig), FASTER_COMPARE_DELAY)
}

// Exploits a comparison timing attack in url
// `url` is the full path to the http endpoint to attack against. The guesses
// will be appended to this string. Ex. "localhost:8771/test?file=foo&signature="
// Endpoint is expected to return 200 when the signature successfully validates
// Returns an empty string if no result is found
func ExploitMoreDifficultTimingAttack(url string, length int) string {
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
