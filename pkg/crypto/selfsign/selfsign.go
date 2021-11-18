// Package selfsign is a test helper that generates self signed certificate.
package selfsign

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var errInvalidPrivateKey = errors.New("selfsign: invalid private key type")

// GenerateSelfSigned creates a self-signed certificate
func GenerateSelfSigned(keyType string) (tls.Certificate, error) {
	pub, priv, err := genKeyPair(keyType)
	if err != nil {
		return tls.Certificate{}, err
	}

	return SelfSign(pub, priv)
}

// GenerateSelfSignedWithDNS creates a self-signed certificate
func GenerateSelfSignedWithDNS(keyType string, cn string, sans ...string) (tls.Certificate, error) {
	pub, priv, err := genKeyPair(keyType)
	if err != nil {
		return tls.Certificate{}, err
	}

	return WithDNS(pub, priv, cn, sans...)
}

func genKeyPair(keyType string) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch keyType {
	case "ed25519":
		return ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return priv.Public(), priv, err
	case "rsa":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		return priv.Public(), priv, err
	case "dss":
		var priv dsa.PrivateKey
		err := dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160)
		if err != nil {
			return nil, nil, err
		}
		err = dsa.GenerateKey(&priv, rand.Reader)
		return &priv.PublicKey, &priv, err
	}
	return nil, nil, fmt.Errorf("unknown key type: %s", keyType)
}

// SelfSign creates a self-signed certificate from a elliptic curve key
func SelfSign(pub crypto.PublicKey, key crypto.PrivateKey) (tls.Certificate, error) {
	return WithDNS(pub, key, hex.EncodeToString(make([]byte, 16)))
}

// WithDNS creates a self-signed certificate from a elliptic curve key
func WithDNS(pubKey crypto.PublicKey, key crypto.PrivateKey, cn string, sans ...string) (tls.Certificate, error) {
	var (
		maxBigInt = new(big.Int) // Max random value, a 130-bits integer, i.e 2^130 - 1
	)

	/* #nosec */
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	/* #nosec */
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return tls.Certificate{}, err
	}

	names := []string{cn}
	names = append(names, sans...)

	template := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          serialNumber,
		Version:               2,
		IsCA:                  true,
		DNSNames:              names,
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{raw},
		PrivateKey:  key,
		Leaf:        &template,
	}, nil
}
