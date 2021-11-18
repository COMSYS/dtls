package dtls

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/pion/dtls/v2/internal/cipherspec"
	"github.com/pion/dtls/v2/pkg/crypto/keyexchange"
	"github.com/pion/dtls/v2/pkg/crypto/prf"
	cs "github.com/pion/dtls/v2/pkg/protocol/ciphersuite"
	"hash"

	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

// CipherSuiteAuthenticationType controls what authentication method is using during the handshake for a CipherSuite
type CipherSuiteAuthenticationType = cipherspec.AuthenticationType

// AuthenticationType Enums
const (
	CipherSuiteAuthenticationTypeCertificate  CipherSuiteAuthenticationType = cipherspec.AuthenticationTypeCertificate
	CipherSuiteAuthenticationTypePreSharedKey CipherSuiteAuthenticationType = cipherspec.AuthenticationTypePreSharedKey
	CipherSuiteAuthenticationTypeAnonymous    CipherSuiteAuthenticationType = cipherspec.AuthenticationTypeAnonymous
)

var _ = allCipherSuites() // Necessary until this function isn't only used by Go 1.14

// CipherSuite is an interface that all DTLS CipherSuites must satisfy
type CipherSuite interface {
	// String of CipherSuite, only used for logging
	String() string

	// ID of CipherSuite.
	ID() cs.ID

	// What type of Certificate does this CipherSuite use
	CertificateType() clientcertificate.Type

	KeyExchange() keyexchange.Type

	// What Hash function is used during verification
	HashFunc() func() hash.Hash

	// What Hash function is used to construct HMAC for derivig master secret
	PrfHashFunc() prf.HashFunc

	// AuthenticationType controls what authentication method is using during the handshake
	AuthenticationType() CipherSuiteAuthenticationType

	// Called when keying material has been generated, should initialize the internal cipher
	Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error
	IsInitialized() bool

	Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	Decrypt(in []byte) ([]byte, error)
}

// CipherSuiteName provides the same functionality as tls.CipherSuiteName
// that appeared first in Go 1.14.
//
// Our implementation differs slightly in that it takes in a CiperSuiteID,
// like the rest of our library, instead of a uint16 like crypto/tls.
func CipherSuiteName(id cs.ID) string {
	suite := cipherspec.CipherSuiteForID(id)
	if suite != nil {
		return suite.String()
	}
	return fmt.Sprintf("0x%04X", uint16(id))
}

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function.
func cipherSuiteForID(id cs.ID, customCiphers func() []CipherSuite) CipherSuite {
	suite := cipherspec.CipherSuiteForID(id)
	if suite != nil {
		return suite
	}
	if customCiphers != nil {
		for _, c := range customCiphers() {
			if c.ID() == id {
				return c
			}
		}
	}

	return nil
}

// CipherSuites we support in order of preference
func defaultCipherSuites() []cs.ID {
	return []cs.ID{
		cs.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		cs.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		cs.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		cs.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		cs.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		cs.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		cs.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		cs.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
		cs.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		cs.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		cs.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		cs.TLS_RSA_WITH_AES_128_CBC_SHA,
		cs.TLS_RSA_WITH_AES_256_CBC_SHA,
		cs.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		cs.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
}

func allCipherSuites() []cs.ID {
	return []cs.ID{
		cs.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		cs.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		cs.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		cs.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
		cs.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		cs.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		cs.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		cs.TLS_PSK_WITH_AES_128_CCM,
		cs.TLS_PSK_WITH_AES_128_CCM_8,
		cs.TLS_PSK_WITH_AES_128_GCM_SHA256,
		cs.TLS_PSK_WITH_AES_128_CBC_SHA256,
	}
}

var ThesisRecommended []cs.ID = []cs.ID{
	cs.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	cs.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	cs.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	cs.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
	cs.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
	cs.TLS_DHE_RSA_WITH_AES_256_CCM,
	cs.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	cs.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	cs.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	cs.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
	cs.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	cs.TLS_DHE_RSA_WITH_AES_128_CCM,
	cs.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	cs.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	cs.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	cs.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	cs.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	cs.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
	cs.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	cs.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	cs.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	// not explicitly recommended by BSI, but by NIST
	cs.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
	cs.TLS_DHE_RSA_WITH_AES_256_CCM_8,
	cs.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	cs.TLS_DHE_RSA_WITH_AES_128_CCM_8,
	cs.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
}

var ThesisNoPFS []cs.ID = []cs.ID{
	cs.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	cs.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
	cs.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
	cs.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
	cs.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
	cs.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	cs.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
	cs.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
	cs.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	cs.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	cs.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
	cs.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
	cs.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
	cs.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	cs.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
	cs.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
}

var ThesisInsecure []cs.ID = []cs.ID{
	cs.TLS_NULL_WITH_NULL_NULL,
	cs.TLS_RSA_WITH_NULL_MD5,
	cs.TLS_RSA_WITH_NULL_SHA,
	cs.TLS_RSA_WITH_NULL_SHA256,
	cs.TLS_ECDH_ECDSA_WITH_NULL_SHA,
	cs.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
	cs.TLS_ECDH_RSA_WITH_NULL_SHA,
	cs.TLS_ECDHE_RSA_WITH_NULL_SHA,
	cs.TLS_ECDH_ANON_WITH_NULL_SHA,
	cs.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
	cs.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	cs.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
	cs.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	cs.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	cs.TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
	cs.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
	cs.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
	cs.TLS_RSA_WITH_DES_CBC_SHA,
	cs.TLS_DH_DSS_WITH_DES_CBC_SHA,
	cs.TLS_DH_RSA_WITH_DES_CBC_SHA,
	cs.TLS_DHE_DSS_WITH_DES_CBC_SHA,
	cs.TLS_DHE_RSA_WITH_DES_CBC_SHA,
	cs.TLS_DH_ANON_WITH_DES_CBC_SHA,
	cs.TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA,
	cs.TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA,
	cs.TLS_DH_ANON_WITH_AES_128_CBC_SHA256,
	cs.TLS_DH_ANON_WITH_AES_256_CBC_SHA256,
	cs.TLS_DH_ANON_WITH_AES_128_GCM_SHA256,
	cs.TLS_DH_ANON_WITH_AES_256_GCM_SHA384,
	cs.TLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
	cs.TLS_ECDH_ANON_WITH_AES_256_CBC_SHA,
	// 3DES might still be considered weakly secure?
	//cs.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	//cs.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
	//cs.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	//cs.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	//cs.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	//cs.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
	//cs.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	//cs.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
	//cs.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,

	//?
	//cs.TLS_RSA_WITH_AES_128_CBC_SHA,
	//cs.TLS_RSA_WITH_AES_128_CBC_SHA256,
	//cs.TLS_RSA_WITH_AES_256_CBC_SHA256,
	//cs.TLS_RSA_WITH_AES_128_CCM,
	//cs.TLS_RSA_WITH_AES_256_CCM,
	//cs.TLS_RSA_WITH_AES_128_CCM_8,
	//cs.TLS_RSA_WITH_AES_256_CCM_8,
}

func cipherSuiteIDs(cipherSuites []CipherSuite) []uint16 {
	rtrn := []uint16{}
	for _, c := range cipherSuites {
		rtrn = append(rtrn, uint16(c.ID()))
	}
	return rtrn
}

func parseCipherSuites(userSelectedSuites []cs.ID, customCipherSuites func() []CipherSuite, includeCertificateSuites, includePSKSuites bool) ([]CipherSuite, error) {
	cipherSuitesForIDs := func(ids []cs.ID) ([]CipherSuite, error) {
		cipherSuites := []CipherSuite{}
		for _, id := range ids {
			c := cipherSuiteForID(id, nil)
			if c == nil {
				return nil, &invalidCipherSuite{id}
			}
			cipherSuites = append(cipherSuites, c)
		}
		return cipherSuites, nil
	}

	var (
		cipherSuites []CipherSuite
		err          error
		i            int
	)
	if userSelectedSuites != nil {
		cipherSuites, err = cipherSuitesForIDs(userSelectedSuites)
		if err != nil {
			return nil, err
		}
	} else {
		cipherSuites, err = cipherSuitesForIDs(defaultCipherSuites())
		if err != nil {
			return nil, err
		}
	}

	// Put CustomCipherSuites before ID selected suites
	if customCipherSuites != nil {
		cipherSuites = append(customCipherSuites(), cipherSuites...)
	}

	var foundCertificateSuite, foundPSKSuite, foundAnonymousSuite bool
	for _, c := range cipherSuites {
		switch {
		case includeCertificateSuites && c.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate:
			foundCertificateSuite = true
		case includePSKSuites && c.AuthenticationType() == CipherSuiteAuthenticationTypePreSharedKey:
			foundPSKSuite = true
		case c.AuthenticationType() == CipherSuiteAuthenticationTypeAnonymous:
			foundAnonymousSuite = true
		default:
			continue
		}
		cipherSuites[i] = c
		i++
	}

	switch {
	case includeCertificateSuites && !foundCertificateSuite && !foundAnonymousSuite:
		return nil, errNoAvailableCertificateCipherSuite
	case includePSKSuites && !foundPSKSuite:
		return nil, errNoAvailablePSKCipherSuite
	case i == 0:
		return nil, errNoAvailableCipherSuites
	}

	return cipherSuites[:i], nil
}

func parseAllCipherSuites(userSelectedSuites []cs.ID) ([]CipherSuite, error) {
	cipherSuites := make([]CipherSuite, len(userSelectedSuites))
	for i, id := range userSelectedSuites {
		c := cipherSuiteForID(id, nil)
		if c == nil {
			c = &dummySuite{id}
		}
		cipherSuites[i] = c
	}
	return cipherSuites, nil
}

type dummySuite struct {
	id cs.ID
}

func (d *dummySuite) String() string {
	return d.id.String()
}

func (d *dummySuite) ID() cs.ID {
	return d.id
}

func (d *dummySuite) CertificateType() clientcertificate.Type {
	return 0
}

func (d *dummySuite) KeyExchange() keyexchange.Type {
	return 0
}

func (d *dummySuite) HashFunc() func() hash.Hash {
	return sha256.New
}

func (d *dummySuite) PrfHashFunc() prf.HashFunc {
	return sha256.New
}

func (d *dummySuite) AuthenticationType() CipherSuiteAuthenticationType {
	return 0
}

func (d *dummySuite) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	return errors.New("suite not implemented")
}

func (d *dummySuite) IsInitialized() bool {
	return false
}

func (d *dummySuite) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	return nil, errors.New("suite not implemented")
}

func (d *dummySuite) Decrypt(in []byte) ([]byte, error) {
	return nil, errors.New("suite not implemented")
}
