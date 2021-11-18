// Package clientcertificate provides all the support Client Certificate types
package clientcertificate

import (
	"encoding/json"
	"fmt"
)

// Type is used to communicate what
// type of certificate is being transported
//
//https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-2
type Type byte

// ClientCertificateType enums
const (
	RSASign    Type = 1
	DSSSign    Type = 2
	RSAFixedDH Type = 3
	DSSFixedDH Type = 4
	ECDSASign  Type = 64
)

// Types returns all valid ClientCertificate Types
func Types() map[Type]bool {
	return map[Type]bool{
		RSASign:   true,
		ECDSASign: true,
	}
}

var clientCertificateTypeToName = map[Type]string{
	1:  "rsa_sign",
	2:  "dss_sign",
	3:  "rsa_fixed_dh",
	4:  "dss_fixed_dh",
	64: "ecdsa_sign",
}

func (t Type) MarshalJSON() ([]byte, error) {
	h, ok := clientCertificateTypeToName[t]
	if !ok {
		return json.Marshal(fmt.Sprintf("unknown(%d)", int(t)))
	}
	return json.Marshal(h)
}
