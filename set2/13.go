/*
 * ECB cut-and-paste
 *
 * Write a k=v parsing routine, as if for a structured cookie. The routine
 * should take:
 *
 *     foo=bar&baz=qux&zap=zazzle
 *
 * ... and produce:
 *
 *
 *     {
 *	     foo: 'bar',
 *       baz: 'qux',
 *       zap: 'zazzle'
 *     }
 *
 * (you know, the object; I don't care if you convert it to JSON).
 *
 * Now write a function that encodes a user profile in that format, given an
 * email address. You should have something like:
 *
 *     profile_for("foo@bar.com")
 *
 * ... and it should produce:
 *
 *     {
 *       email: 'foo@bar.com',
 *       uid: 10,
 *       role: 'user'
 *     }
 *
 * ... encoded as:
 *
 *     email=foo@bar.com&uid=10&role=user
 *
 * Your "profile_for" function should not allow encoding metacharacters
 * (& and =). Eat them, quote them, whatever you want to do, but don't let
 * people set their email address to "foo@bar.com&role=admin".
 *
 * Now, two more easy functions. Generate a random AES key, then:
 *
 *   a. Encrypt the encoded user profile under the key; "provide" that to the
 *      "attacker".
 *   b. Decrypt the encoded user profile and parse it.
 *
 * Using only the user input to profile_for() (as an oracle to generate "valid"
 * ciphertexts) and the ciphertexts themselves, make a role=admin profile.
 *
 * Notes/Theories:
 *
 * Make an email long enough so that the last block is the value of the role:
 *
 *    |    block   |          |
 *     uid=10&role= user
 *
 * Determine what an empty "admin" block looks like, then replace the last block
 * with it.
 */

package set_two

import (
	"fmt"
	"strings"
)

func stripMetachars(s string) string {
	metachars := []string{"&", "="}
	for _, char := range metachars {
		s = strings.Replace(s, char, "", -1)
	}
	return s
}

func ProfileFor(email string) string {
	email = stripMetachars(email)
	return fmt.Sprintf("email=%s&uid=10&role=user", email)
}
