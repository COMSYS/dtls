// Package signature provides our implemented Signature Algorithms
package signature

import "encoding/json"

// Algorithm as defined in TLS 1.2
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
type Algorithm uint16

// SignatureAlgorithm enums
const (
	Anonymous Algorithm = 0
	RSA       Algorithm = 1
	ECDSA     Algorithm = 3
	Ed25519   Algorithm = 7
)

// Algorithms returns all implemented Signature Algorithms
func Algorithms() map[Algorithm]struct{} {
	return map[Algorithm]struct{}{
		Anonymous: {},
		RSA:       {},
		ECDSA:     {},
		Ed25519:   {},
	}
}

var signatureAlgorithmToName = map[Algorithm]string{
	Anonymous: "Anon",
	RSA:       "RSA",
	ECDSA:     "ECDSA",
	Ed25519:   "Ed25519",
}

func (s Algorithm) MarshalJSON() ([]byte, error) {
	name, ok := signatureAlgorithmToName[s]
	if !ok {
		return json.Marshal(uint16(s))
	}
	return json.Marshal(name)
}
