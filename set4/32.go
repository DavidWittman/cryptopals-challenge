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
	"fmt"
	"net/http"
	"strings"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

// Sleep for this many milliseconds while comparing the signature
const FASTER_COMPARE_DELAY = 5

// Number of HTTP requests to average when exploiting attack
const REQUESTS_TO_TIME = 4

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
	fmt.Println(goodSig)
	return InsecureCompare([]byte(signature), []byte(goodSig), FASTER_COMPARE_DELAY)
}

// Same as Challenge 31, except this times multiple HTTP requests and compares the averages
func ExploitMoreDifficultTimingAttack(url string, length int) string {
	var known string

	// These are the characters we're brute-forcing
	chars := "0123456789abcdef"

	for i := 0; i < length; i++ {
		requests := make(map[string]int64)
		// Fill in the rest of the signature with a character that won't match
		filler := strings.Repeat("_", length-(i+1))

		for j := 0; j < len(chars); j++ {
			signature := strings.Join([]string{known, string(chars[j]), filler}, "")
			fmt.Println(signature)
			urlWithSig := strings.Join([]string{url, signature}, "")

			// Issue REQUESTS_TO_TIME requests for this character and return the average
			res := TimeSomeHTTPRequests(urlWithSig, string(chars[j]))

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

// The same thing as TimeHTTPRequest, but issues multiple requests w/ goroutines
// and averages the results. Number of requests can be configured with the
// REQUESTS_TO_TIME constant.
func TimeSomeHTTPRequests(url, id string) timedResponse {
	var (
		average int64
		res     timedResponse
	)

	// These are the results just for this specific set of requests
	results := make(chan timedResponse)

	for i := 0; i < REQUESTS_TO_TIME; i++ {
		go TimeHTTPRequest(url, id, results)
	}
	// TODO(dw): This works... sometimes. It might be better to take these
	// guesses and remove the outliers (i.e. the longest request) then take
	// take the average
	for i := 0; i < REQUESTS_TO_TIME; i++ {
		res = <-results
		// Short circuit if we get a 200
		if res.r.StatusCode == http.StatusOK {
			return res
		}
		average += (res.elapsed / int64(REQUESTS_TO_TIME))
	}

	return timedResponse{res.r, id, average}
}
