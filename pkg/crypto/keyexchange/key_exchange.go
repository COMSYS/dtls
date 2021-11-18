package keyexchange

import (
	"fmt"
	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
)

type Type uint

const (
	NULL Type = iota
	DHE_DSS
	DHE_RSA
	DH_ANON
	RSA
	DH_DSS
	DH_RSA
	ECDH_ECDSA
	ECDHE_ECDSA
	ECDH_RSA
	ECDHE_RSA
	ECDH_ANON
	PSK
	DHE_PSK
	RSA_PSK
	RSA_EXPORT
)

func (c Type) CertificateType() clientcertificate.Type {
	switch c {
	case NULL, DH_ANON, ECDH_ANON:
		return clientcertificate.Type(0)
	case RSA, RSA_PSK, DHE_RSA, ECDHE_RSA:
		return clientcertificate.RSASign
	case DH_DSS, DHE_DSS:
		return clientcertificate.DSSSign
	case ECDHE_ECDSA:
		return clientcertificate.ECDSASign
	default:
		return clientcertificate.Type(0)
	}
}

func (c Type) IsAnonymous() bool {
	return c == DH_ANON || c == ECDH_ANON || c == NULL
}

func (c Type) IsPsk() bool {
	return c == PSK || c == DHE_PSK || c == RSA_PSK
}

func (c Type) RequiresServerKeyExchange() bool {
	return c == RSA_EXPORT || c == DHE_DSS || c == DHE_RSA || c == DH_ANON || c == ECDHE_ECDSA || c == ECDHE_RSA
}

func (c Type) String() string {
	switch c {
	case NULL:
		return "NULL"
	case DHE_DSS:
		return "DHE_DSS"
	case DHE_RSA:
		return "DHE_RSA"
	case DH_ANON:
		return "DH_ANON"
	case RSA:
		return "RSA"
	case DH_DSS:
		return "DH_DSS"
	case DH_RSA:
		return "DH_RSA"
	case ECDH_ECDSA:
		return "ECDH_ECDSA"
	case ECDHE_ECDSA:
		return "ECDHE_ECDSA"
	case ECDH_RSA:
		return "ECDH_RSA"
	case ECDHE_RSA:
		return "ECDHE_RSA"
	case ECDH_ANON:
		return "ECDH_ANON"
	case PSK:
		return "PSK"
	case DHE_PSK:
		return "DHE_PSK"
	case RSA_PSK:
		return "RSA_PSK"
	case RSA_EXPORT:
		return "RSA_EXPORT"
	default:
		return fmt.Sprintf("unknown(%d)", c)
	}
}
