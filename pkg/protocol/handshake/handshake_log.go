package handshake

import (
	"encoding/json"
	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v2/pkg/crypto/elliptic"
	"github.com/pion/dtls/v2/pkg/crypto/hash"
	"github.com/pion/dtls/v2/pkg/crypto/signature"
	"github.com/pion/dtls/v2/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v2/pkg/protocol"
	cs "github.com/pion/dtls/v2/pkg/protocol/ciphersuite"
	"github.com/pion/dtls/v2/pkg/protocol/extension"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"time"
)

type ServerHello struct {
	Version protocol.Version `json:"version"`
	Random  Random           `json:"random"`

	CipherSuite         cs.ID                        `json:"cipher_suite"`
	CompressionMethod   protocol.CompressionMethodID `json:"compression_method,omitempty"`
	OcspStapling        bool                         `json:"ocsp_stapling,omitempty"`
	Ticket              bool                         `json:"ticket,omitempty"`
	SecureRenegotiation bool                         `json:"secure_renegotiation"`
	Heartbeat           bool                         `json:"heartbeat,omitempty"`
	EMS                 bool                         `json:"extended_master_secret,omitempty"`
	Extensions          extension.Extensions         `json:"extensions,omitempty"`
}

type ClientHello struct {
	Version            protocol.Version              `json:"version,omitempty"`
	Random             Random                        `json:"random,omitempty"`
	Cookie             []byte                        `json:"cookie,omitempty"`
	CipherSuites       []cs.ID                       `json:"cipher_suites,omitempty"`
	CompressionMethods []*protocol.CompressionMethod `json:"compression_methods,omitempty"`
	Extensions         extension.Extensions          `json:"extensions,omitempty"`
}

// SimpleCertificate holds a *x509.Certificate and a []byte for the certificate
type SimpleCertificate struct {
	Raw    []byte            `json:"raw,omitempty"`
	Parsed *x509.Certificate `json:"parsed,omitempty"`
}

// Certificates represents a TLS certificates message in a format friendly to the golang JSON library.
// ValidationError should be non-nil whenever Valid is false.
type Certificates struct {
	Certificate SimpleCertificate   `json:"certificate,omitempty"`
	Chain       []SimpleCertificate `json:"chain,omitempty"`
	Validation  *x509.Validation    `json:"validation,omitempty"`
}

// ServerKeyExchange represents the raw key data sent by the server in TLS key exchange message
type ServerKeyExchange struct {
	IdentityHint       []byte              `json:"identity_hint,omitempty"`
	EllipticCurveType  elliptic.CurveType  `json:"elliptic_curve_type,omitempty"`
	NamedCurve         elliptic.Curve      `json:"named_curve,omitempty"`
	PublicKey          []byte              `json:"public_key,omitempty"`
	HashAlgorithm      hash.Algorithm      `json:"hash_algorithm,omitempty"`
	SignatureAlgorithm signature.Algorithm `json:"signature_algorithm,omitempty"`
	Signature          []byte              `json:"signature,omitempty"`
}

// ClientKeyExchange represents the raw key data sent by the client in TLS key exchange message
type ClientKeyExchange struct {
	IdentityHint []byte `json:"identity_hint,omitempty"`
	PublicKey    []byte `json:"public_key,omitempty"`
}

// Finished represents a TLS Finished message
type Finished struct {
	VerifyData []byte `json:"verify_data"`
}

// SessionTicket represents the new session ticket sent by the server to the
// client
type SessionTicket struct {
	Value        []uint8 `json:"value,omitempty"`
	Length       int     `json:"length,omitempty"`
	LifetimeHint uint32  `json:"lifetime_hint,omitempty"`
}

type Secret struct {
	Value  []byte `json:"value,omitempty"`
	Length int    `json:"length,omitempty"`
}

// KeyMaterial explicitly represent the cryptographic values negotiated by
// the client and server
type KeyMaterial struct {
	MasterSecret    *Secret `json:"master_secret,omitempty"`
	PreMasterSecret *Secret `json:"pre_master_secret,omitempty"`
}

type HelloVerifyRequest struct {
	Version protocol.Version `json:"version,omitempty"`
	Cookie  []byte           `json:"cookie,omitempty"`
}

type RequestedCertificates struct {
	ClientCertificateType     []clientcertificate.Type  `json:"client_certificate_type,omitempty"`
	SignatureAndHashAlgorithm []signaturehash.Algorithm `json:"signature_and_hash_algorithm,omitempty"`
	DistinguishedName         []pkix.Name               `json:"dn,omitempty"`
}

type CertificateVerify struct {
	HashAlgorithm      hash.Algorithm      `json:"hash_algorithm,omitempty"`
	SignatureAlgorithm signature.Algorithm `json:"signature_algorithm,omitempty"`
	Signature          []byte              `json:"signature,omitempty"`
}

type ServerHandshake struct {
	ClientHello        *ClientHello           `json:"client_hello,omitempty"`
	ServerHello        *ServerHello           `json:"server_hello,omitempty"`
	ServerCertificates *Certificates          `json:"server_certificates,omitempty"`
	ClientCertificates *Certificates          `json:"client_certificates,omitempty"`
	ServerKeyExchange  *ServerKeyExchange     `json:"server_key_exchange,omitempty"`
	ClientKeyExchange  *ClientKeyExchange     `json:"client_key_exchange,omitempty"`
	ClientFinished     *Finished              `json:"client_finished,omitempty"`
	SessionTicket      *SessionTicket         `json:"session_ticket,omitempty"`
	ServerFinished     *Finished              `json:"server_finished,omitempty"`
	KeyMaterial        *KeyMaterial           `json:"key_material,omitempty"`
	HelloVerifyRequest *HelloVerifyRequest    `json:"hello_verify_request,omitempty"`
	CertificateRequest *RequestedCertificates `json:"requested_certificates,omitempty"`
	CertificateVerify  *CertificateVerify     `json:"certificate_verify,omitempty"`
}

func (c *MessageServerHello) MakeLog() *ServerHello {
	sh := &ServerHello{}
	sh.Version = c.Version
	sh.CipherSuite = cs.ID(*c.CipherSuiteID)
	sh.CompressionMethod = c.CompressionMethod.ID
	for _, ext := range c.Extensions {
		switch ext.TypeValue() {
		case extension.UseExtendedMasterSecretTypeValue:
			if ems, ok := ext.(*extension.UseExtendedMasterSecret); ok {
				sh.EMS = ems.Supported
			}
		case extension.SessionTicket:
			sh.Ticket = true
		case extension.RenegotiationInfoTypeValue:
			sh.SecureRenegotiation = true
		case extension.StatusRequest:
			sh.OcspStapling = true
		}
	}
	sh.Extensions = c.Extensions
	sh.Random = c.Random
	return sh
}

func (c *MessageHelloVerifyRequest) MakeLog() *HelloVerifyRequest {
	vr := new(HelloVerifyRequest)
	vr.Version = c.Version
	vr.Cookie = make([]byte, len(c.Cookie))
	copy(vr.Cookie, c.Cookie)
	return vr
}

func (c *MessageClientHello) MakeLog() *ClientHello {
	ch := new(ClientHello)
	ch.Version = c.Version
	ch.Random = c.Random
	ch.Cookie = c.Cookie
	ch.CipherSuites = make([]cs.ID, len(c.CipherSuiteIDs))
	for i, c := range c.CipherSuiteIDs {
		ch.CipherSuites[i] = cs.ID(c)
	}
	ch.CompressionMethods = c.CompressionMethods
	ch.Extensions = c.Extensions

	return ch
}

func (c *MessageServerKeyExchange) MakeLog() *ServerKeyExchange {
	ske := new(ServerKeyExchange)
	ske.IdentityHint = c.IdentityHint
	ske.EllipticCurveType = c.EllipticCurveType
	ske.NamedCurve = c.NamedCurve
	ske.PublicKey = c.PublicKey
	ske.HashAlgorithm = c.HashAlgorithm
	ske.SignatureAlgorithm = c.SignatureAlgorithm
	ske.Signature = c.Signature
	return ske
}

func (c *MessageCertificate) MakeLog() *Certificates {
	certs := new(Certificates)

	if len(c.Certificate) == 0 {
		return certs
	}
	if len(c.Certificate) >= 1 {
		cert := c.Certificate[0]
		certs.Certificate.Raw = make([]byte, len(cert))
		copy(certs.Certificate.Raw, cert)
	}
	if len(c.Certificate) >= 2 {
		chain := c.Certificate[1:]
		certs.Chain = make([]SimpleCertificate, len(chain))
		for idx, cert := range chain {
			certs.Chain[idx].Raw = make([]byte, len(cert))
			copy(certs.Chain[idx].Raw, cert)
		}
	}

	certificates := make([]*x509.Certificate, len(c.Certificate))
	for i, raw := range c.Certificate {
		cert, err := x509.ParseCertificate(raw)
		if err == nil {
			certificates[i] = cert
		}
	}
	var intermediateCAPool *x509.CertPool
	if len(certificates) > 1 {
		intermediateCAPool = x509.NewCertPool()
		for _, cert := range certificates[1:] {
			intermediateCAPool.AddCert(cert)
		}
	}
	_, _, _, err := certificates[0].Verify(x509.VerifyOptions{
		CurrentTime:   time.Now(),
		Intermediates: intermediateCAPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	validation := &x509.Validation{
		BrowserTrusted: err == nil,
	}
	if err != nil {
		validation.BrowserError = err.Error()
	}

	certs.addParsed(certificates, validation)

	return certs
}

// addParsed sets the parsed certificates and the validation. It assumes the
// chain slice has already been allocated.
func (c *Certificates) addParsed(certs []*x509.Certificate, validation *x509.Validation) {
	if len(certs) >= 1 {
		c.Certificate.Parsed = certs[0]
	}
	if len(certs) >= 2 {
		chain := certs[1:]
		for idx, cert := range chain {
			c.Chain[idx].Parsed = cert
		}
	}
	c.Validation = validation
}

func (c *MessageCertificateRequest) MakeLog() *RequestedCertificates {
	certs := new(RequestedCertificates)

	certs.ClientCertificateType = c.CertificateTypes
	certs.SignatureAndHashAlgorithm = c.SignatureHashAlgorithms
	return certs
}

func (c *MessageClientKeyExchange) MakeLog() *ClientKeyExchange {
	cke := new(ClientKeyExchange)
	cke.IdentityHint = c.IdentityHint
	cke.PublicKey = c.PublicKey
	return cke
}

func (c *MessageCertificateVerify) MakeLog() *CertificateVerify {
	cv := new(CertificateVerify)
	cv.HashAlgorithm = c.HashAlgorithm
	cv.SignatureAlgorithm = c.SignatureAlgorithm
	cv.Signature = c.Signature[:]
	return cv
}

func (c *MessageFinished) MakeLog() *Finished {
	finished := new(Finished)
	finished.VerifyData = c.VerifyData
	return finished
}

func MakeKeyMaterialLog(preMasterSecret, masterSecret []byte) *KeyMaterial {
	km := new(KeyMaterial)
	km.PreMasterSecret = &Secret{preMasterSecret, len(preMasterSecret)}
	km.MasterSecret = &Secret{masterSecret, len(masterSecret)}
	return km
}

func (p *Random) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.RandomBytes[:])
}
