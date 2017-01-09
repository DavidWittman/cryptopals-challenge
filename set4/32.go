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
	"sort"
	"strings"
	"time"

	"github.com/DavidWittman/cryptopals-challenge/cryptopals"
)

// Sleep for this many milliseconds while comparing the signature
const FASTER_COMPARE_DELAY = 5

// Number of HTTP requests to average when exploiting attack
const REQUESTS_TO_TIME = 5

type timedResponses []timedResponse

func (t timedResponses) Len() int {
	return len(t)
}

func (t timedResponses) Less(i, j int) bool {
	return t[i].elapsed < t[j].elapsed
}

func (t timedResponses) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

func (t timedResponses) Mean() int64 {
	var total int64
	for _, resp := range t {
		total += resp.elapsed
	}
	return total / int64(len(t))
}

func (t timedResponses) Print() {
	fmt.Println(t[0].id)
	for _, tr := range t {
		fmt.Println("\t", tr.elapsed)
	}
}

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
	goodSig := HMACSHA1(cryptopals.RANDOM_KEY, []byte(message))
	return InsecureCompare([]byte(signature), []byte(goodSig), FASTER_COMPARE_DELAY)
}

// Same as Challenge 31, except this times multiple HTTP requests for each
// individual character and then and compares the averages
func ExploitMoreDifficultTimingAttack(url string, length int) string {
	var known string

	// These are the characters we're brute-forcing
	chars := "0123456789abcdef"

	for i := 0; i < length; i++ {
		fmt.Printf("\n\nKNOWN:\t%s\n\n\n", known)
		requests := make(map[string]int64)
		// Fill in the rest of the signature with a character that won't match
		filler := strings.Repeat("_", length-(i+1))

		for j := 0; j < len(chars); j++ {
			signature := strings.Join([]string{known, string(chars[j]), filler}, "")
			urlWithSig := strings.Join([]string{url, signature}, "")

			// Sleep for a little bit between characters to let the webserver calm down
			time.Sleep(time.Millisecond * 200)
			// Issue REQUESTS_TO_TIME requests for this character and return the average
			res := TimeSomeHTTPRequests(urlWithSig, string(chars[j]), REQUESTS_TO_TIME)

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

// The same thing as TimeHTTPRequest, but issues `count`  requests w/ goroutines
// and averages the results.
func TimeSomeHTTPRequests(url, id string, count int) timedResponse {
	var responses timedResponses

	// These are the results just for this specific set of requests
	resultsChan := make(chan timedResponse, count)

	// Start HTTP request workers
	for i := 0; i < count; i++ {
		go TimeHTTPRequest(url, id, resultsChan)
	}

	// Gather results
	for i := 0; i < count; i++ {
		response := <-resultsChan
		// Short circuit if we get a 200
		if response.r.StatusCode == http.StatusOK {
			return response
		}
		responses = append(responses, response)
	}

	// Sort and remove the slowest request to reduce outliers
	sort.Sort(responses)
	responses = responses[:len(responses)-3]

	fmt.Println(responses[0].id, responses.Mean())

	return timedResponse{responses[0].r, id, responses.Mean()}
}
