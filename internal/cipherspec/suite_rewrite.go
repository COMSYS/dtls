package cipherspec

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/pion/dtls/v2/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v2/pkg/crypto/keyexchange"
	"github.com/pion/dtls/v2/pkg/crypto/prf"
	cs "github.com/pion/dtls/v2/pkg/protocol/ciphersuite"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	log "github.com/sirupsen/logrus"
	"hash"
	"sync/atomic"
)

type CipherSpec struct {
	ID      cs.ID
	kex     keyexchange.Type
	cipher  selectedCipher
	mode    mode
	flags   uint16
	macHash crypto.Hash
}

type selectedCipher uint

const (
	nullCipher selectedCipher = iota
	desCipher
	des40
	tripleDes
	des3ede
	aes128
	aes256
)

type mode uint

const (
	nullMode mode = iota
	cbc
	cbc40
	ccm
	gcm
)

const (
	ANON = 1 << iota
	EXPORT
	PSK
	PRF8
)

const noMac = crypto.Hash(0)

var cipherSpec = []CipherSpec{
	{cs.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, keyexchange.ECDHE_ECDSA, aes128, ccm, 0, noMac},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, keyexchange.ECDHE_ECDSA, aes128, ccm, PRF8, noMac},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, keyexchange.ECDHE_ECDSA, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, keyexchange.ECDHE_RSA, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, keyexchange.ECDHE_ECDSA, aes256, cbc, 0, crypto.SHA1},
	{cs.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, keyexchange.ECDHE_RSA, aes256, cbc, 0, crypto.SHA1},
	{cs.TLS_PSK_WITH_AES_128_CCM, keyexchange.PSK, aes128, ccm, PSK, noMac},
	{cs.TLS_PSK_WITH_AES_128_CCM_8, keyexchange.PSK, aes128, ccm, PSK | PRF8, noMac},
	{cs.TLS_PSK_WITH_AES_128_GCM_SHA256, keyexchange.PSK, aes128, cbc, PSK, crypto.SHA256},
	{cs.TLS_PSK_WITH_AES_128_CBC_SHA256, keyexchange.PSK, aes128, cbc, PSK, crypto.SHA256},
	{cs.TLS_NULL_WITH_NULL_NULL, keyexchange.NULL, nullCipher, nullMode, 0, noMac},
	{cs.TLS_RSA_WITH_NULL_MD5, keyexchange.RSA, nullCipher, nullMode, 0, crypto.MD5},
	{cs.TLS_RSA_WITH_NULL_SHA, keyexchange.RSA, nullCipher, nullMode, 0, crypto.SHA1},
	{cs.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, keyexchange.RSA, des40, cbc, EXPORT, crypto.SHA1},
	{cs.TLS_RSA_WITH_DES_CBC_SHA, keyexchange.RSA, desCipher, cbc, 0, crypto.SHA1},
	{cs.TLS_RSA_WITH_3DES_EDE_CBC_SHA, keyexchange.RSA, tripleDes, cbc, 0, crypto.SHA1},
	{cs.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, keyexchange.DH_DSS, des40, cbc, EXPORT, crypto.SHA1},
	{cs.TLS_DH_DSS_WITH_DES_CBC_SHA, keyexchange.DH_DSS, desCipher, cbc, 0, crypto.SHA1},
	{cs.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA, keyexchange.DH_RSA, des40, cbc, EXPORT, crypto.SHA1},
	{cs.TLS_DH_RSA_WITH_DES_CBC_SHA, keyexchange.DH_RSA, desCipher, cbc, 0, crypto.SHA1},
	{cs.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, keyexchange.DHE_DSS, des40, cbc, EXPORT, crypto.SHA1},
	{cs.TLS_DHE_DSS_WITH_DES_CBC_SHA, keyexchange.DHE_DSS, desCipher, cbc, 0, crypto.SHA1},
	{cs.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, keyexchange.DHE_RSA, des40, cbc, 0 | EXPORT, crypto.SHA1},
	{cs.TLS_DHE_RSA_WITH_DES_CBC_SHA, keyexchange.DHE_RSA, des40, cbc, 0, crypto.SHA1},
	{cs.TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA, keyexchange.DH_ANON, des40, cbc, ANON | EXPORT, crypto.SHA1},
	{cs.TLS_DH_ANON_WITH_DES_CBC_SHA, keyexchange.DH_ANON, desCipher, cbc, ANON, crypto.SHA1},
	{cs.TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA, keyexchange.DH_ANON, des3ede, cbc, ANON, crypto.SHA1},
	{cs.TLS_RSA_WITH_AES_128_CBC_SHA, keyexchange.RSA, aes128, cbc, 0, crypto.SHA1},
	{cs.TLS_RSA_WITH_AES_256_CBC_SHA, keyexchange.RSA, aes256, cbc, 0, crypto.SHA1},
	{cs.TLS_RSA_WITH_NULL_SHA256, keyexchange.RSA, nullCipher, nullMode, 0, crypto.SHA256},
	{cs.TLS_DH_DSS_WITH_AES_128_CBC_SHA256, keyexchange.DH_DSS, aes128, cbc, 0, crypto.SHA256},
	{cs.TLS_DH_RSA_WITH_AES_128_CBC_SHA256, keyexchange.DH_RSA, aes128, cbc, 0, crypto.SHA256},
	{cs.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, keyexchange.DHE_DSS, aes128, cbc, 0, crypto.SHA256},
	{cs.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, keyexchange.DHE_RSA, aes128, cbc, 0, crypto.SHA256},
	{cs.TLS_DH_DSS_WITH_AES_256_CBC_SHA256, keyexchange.DH_DSS, aes256, cbc, 0, crypto.SHA256},
	{cs.TLS_DH_RSA_WITH_AES_256_CBC_SHA256, keyexchange.DH_RSA, aes256, cbc, 0, crypto.SHA256},
	{cs.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, keyexchange.DHE_DSS, aes256, cbc, 0, crypto.SHA256},
	{cs.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, keyexchange.DHE_RSA, aes256, cbc, 0, crypto.SHA256},
	{cs.TLS_DH_ANON_WITH_AES_128_CBC_SHA256, keyexchange.DH_ANON, aes128, cbc, ANON, crypto.SHA256},
	{cs.TLS_DH_ANON_WITH_AES_256_CBC_SHA256, keyexchange.DH_ANON, aes256, cbc, ANON, crypto.SHA256},
	{cs.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, keyexchange.DHE_RSA, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, keyexchange.DHE_RSA, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, keyexchange.DH_RSA, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_DH_RSA_WITH_AES_256_GCM_SHA384, keyexchange.DH_RSA, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, keyexchange.DHE_DSS, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, keyexchange.DHE_DSS, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_DH_DSS_WITH_AES_128_GCM_SHA256, keyexchange.DH_DSS, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_DH_DSS_WITH_AES_256_GCM_SHA384, keyexchange.DH_DSS, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_DH_ANON_WITH_AES_128_GCM_SHA256, keyexchange.DH_ANON, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_DH_ANON_WITH_AES_256_GCM_SHA384, keyexchange.DH_ANON, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_ECDH_ECDSA_WITH_NULL_SHA, keyexchange.ECDH_ECDSA, nullCipher, nullMode, 0, crypto.SHA1},
	{cs.TLS_ECDHE_ECDSA_WITH_NULL_SHA, keyexchange.ECDHE_ECDSA, nullCipher, nullMode, 0, crypto.SHA1},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, keyexchange.ECDHE_ECDSA, aes128, cbc, 0, crypto.SHA1},
	{cs.TLS_ECDH_RSA_WITH_NULL_SHA, keyexchange.ECDH_RSA, nullCipher, nullMode, 0, crypto.SHA1},
	{cs.TLS_ECDHE_RSA_WITH_NULL_SHA, keyexchange.ECDHE_RSA, nullCipher, nullMode, 0, crypto.SHA1},
	{cs.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, keyexchange.ECDHE_RSA, des3ede, cbc, 0, crypto.SHA1},
	{cs.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, keyexchange.ECDHE_RSA, aes128, cbc, 0, crypto.SHA1},
	{cs.TLS_ECDH_ANON_WITH_NULL_SHA, keyexchange.ECDH_ANON, nullCipher, nullMode, ANON, crypto.SHA1},
	{cs.TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA, keyexchange.ECDH_ANON, tripleDes, cbc, 0, crypto.SHA1},
	{cs.TLS_ECDH_ANON_WITH_AES_128_CBC_SHA, keyexchange.ECDH_ANON, aes128, cbc, ANON, crypto.SHA1},
	{cs.TLS_ECDH_ANON_WITH_AES_256_CBC_SHA, keyexchange.ECDH_ANON, aes256, cbc, ANON, crypto.SHA1},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, keyexchange.ECDHE_ECDSA, aes128, cbc, ANON, crypto.SHA256},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, keyexchange.ECDHE_ECDSA, aes256, cbc, 0, crypto.SHA384},
	{cs.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, keyexchange.ECDH_ECDSA, aes128, cbc, 0, crypto.SHA256},
	{cs.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, keyexchange.ECDH_ECDSA, aes256, cbc, 0, crypto.SHA384},
	{cs.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, keyexchange.ECDHE_RSA, aes128, cbc, 0, crypto.SHA256},
	{cs.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, keyexchange.ECDHE_RSA, aes256, cbc, 0, crypto.SHA384},
	{cs.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, keyexchange.ECDH_RSA, aes128, cbc, 0, crypto.SHA256},
	{cs.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384, keyexchange.ECDH_RSA, aes256, cbc, 0, crypto.SHA384},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, keyexchange.ECDHE_ECDSA, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, keyexchange.ECDH_ECDSA, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, keyexchange.ECDH_ECDSA, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, keyexchange.ECDHE_RSA, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, keyexchange.ECDH_RSA, aes128, gcm, 0, crypto.SHA256},
	{cs.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, keyexchange.ECDH_RSA, aes256, gcm, 0, crypto.SHA384},
	{cs.TLS_DHE_RSA_WITH_AES_128_CCM, keyexchange.DHE_RSA, aes128, ccm, 0, noMac},
	{cs.TLS_DHE_RSA_WITH_AES_256_CCM, keyexchange.DHE_RSA, aes256, ccm, 0, noMac},
	{cs.TLS_DHE_RSA_WITH_AES_128_CCM_8, keyexchange.DHE_RSA, aes128, ccm, 0, noMac},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, keyexchange.ECDHE_ECDSA, aes256, ccm, 0, noMac},
	{cs.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, keyexchange.ECDHE_ECDSA, aes256, ccm, PRF8, noMac},
}

type CipherSuite interface {
	String() string
	ID() cs.ID
	CertificateType() clientcertificate.Type
	HashFunc() func() hash.Hash
	PrfHashFunc() prf.HashFunc
	AuthenticationType() AuthenticationType
	KeyExchange() keyexchange.Type
	Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error
	IsInitialized() bool
	Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	Decrypt(in []byte) ([]byte, error)
}

func CipherSuiteForID(id cs.ID) CipherSuite {
	var spec *CipherSpec
	for _, s := range cipherSpec {
		if id == s.ID {
			spec = &s
			break
		}
	}
	if spec == nil {
		return nil
	}
	return newSuiteInstance(spec)
}

func newSuiteInstance(spec *CipherSpec) CipherSuite {
	return &SuiteInstance{
		spec: spec,
	}
}

// Aes128Ccm is a base class used by multiple AES-CCM Ciphers
type SuiteInstance struct {
	spec   *CipherSpec
	cipher atomic.Value
}

// CertificateType returns what type of certificate this CipherSuite exchanges
func (c *SuiteInstance) CertificateType() clientcertificate.Type {
	return c.spec.kex.CertificateType()
}

// ID returns the ID of the CipherSuite
func (c *SuiteInstance) ID() cs.ID {
	return c.spec.ID
}

func (c *SuiteInstance) String() string {
	return c.spec.ID.String()
}

// HashFunc returns the hashing func for this CipherSuite
func (c *SuiteInstance) HashFunc() func() hash.Hash {
	return cryptoToHashFunc(c.spec.macHash)
}

func (c *SuiteInstance) PrfHashFunc() prf.HashFunc {
	if c.spec.macHash == crypto.SHA384 {
		return cryptoToHashFunc(crypto.SHA384)
	}
	return cryptoToHashFunc(crypto.SHA256)
}

func cryptoToHashFunc(c crypto.Hash) func() hash.Hash {
	switch c {
	case crypto.MD5:
		return md5.New
	case crypto.SHA1:
		return sha1.New
	case crypto.SHA256:
		return sha256.New
	case crypto.SHA384:
		return sha512.New384
	default:
		return newNullHash
	}
}

// AuthenticationType controls what authentication method is using during the handshake
func (c *SuiteInstance) AuthenticationType() AuthenticationType {
	if c.spec.flags&PSK > 0 {
		return AuthenticationTypePreSharedKey
	}
	if c.spec.flags&ANON > 0 {
		return AuthenticationTypeAnonymous
	}
	return AuthenticationTypeCertificate
}

func (c *SuiteInstance) KeyExchange() keyexchange.Type {
	return c.spec.kex
}

// IsInitialized returns if the CipherSuite has keying material and can
// encrypt/decrypt packets
func (c *SuiteInstance) IsInitialized() bool {
	return c.cipher.Load() != nil
}

// Init initializes the internal Cipher with keying material
func (c *SuiteInstance) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	var prfMacLen int
	var prfKeyLen int
	var prfIvLen int

	switch c.spec.macHash {
	case crypto.MD5:
		prfMacLen = 16
	case crypto.SHA1:
		prfMacLen = 20
	case crypto.SHA256:
		prfMacLen = 32
	case crypto.SHA384:
		prfMacLen = 48
	}
	var newCipherFunc func(key []byte) (cipher.Block, error)
	switch c.spec.cipher {
	case des40:
		prfKeyLen = 5
		prfIvLen = 8
		newCipherFunc = des.NewCipher
	case desCipher:
		prfKeyLen = 8
		prfIvLen = 8
		newCipherFunc = des.NewCipher
	case tripleDes, des3ede:
		prfKeyLen = 24
		prfIvLen = 8
		newCipherFunc = des.NewTripleDESCipher
	case aes128:
		prfKeyLen = 16
		prfIvLen = 16
		newCipherFunc = aes.NewCipher
	case aes256:
		prfKeyLen = 32
		prfIvLen = 16
		newCipherFunc = aes.NewCipher
	case nullCipher:
		prfKeyLen = 0
		prfIvLen = 0
	default:
		fmt.Errorf("unknown cipher: %d", c.spec.cipher)
	}
	switch c.spec.mode {
	case ccm:
		prfIvLen = 4
		prfMacLen = 0
	case gcm:
		prfIvLen = 4
		prfMacLen = 0
	}
	keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.PrfHashFunc())
	if err != nil {
		return err
	}

	log.Debugf("Client Random: %X", clientRandom)
	log.Debugf("Server Random: %X", serverRandom)
	log.Debugf("Master Secret: %X", masterSecret)
	log.Debugf("Client MAC Key: %X", keys.ClientMACKey)
	log.Debugf("Server MAC Key: %X", keys.ServerMACKey)
	log.Debugf("Client Write Key: %X", keys.ClientWriteKey)
	log.Debugf("Server Write Key: %X", keys.ServerWriteKey)
	log.Debugf("Client Write IV: %X", keys.ClientWriteIV)
	log.Debugf("Server Write IV: %X", keys.ServerWriteIV)

	var localKey, localIv, localMacKey, remoteKey, remoteIv, remoteMacKey []byte
	if isClient {
		localKey = keys.ClientWriteKey
		localIv = keys.ClientWriteIV
		localMacKey = keys.ClientMACKey
		remoteKey = keys.ServerWriteKey
		remoteIv = keys.ServerWriteIV
		remoteMacKey = keys.ServerMACKey
	} else {
		localKey = keys.ServerWriteKey
		localIv = keys.ServerWriteIV
		localMacKey = keys.ServerMACKey
		remoteKey = keys.ClientWriteKey
		remoteIv = keys.ClientWriteIV
		remoteMacKey = keys.ClientMACKey
	}
	switch c.spec.mode {
	case ccm:
		var cph *ciphersuite.CCM
		l := ciphersuite.CCMTagLength
		if c.spec.flags&PRF8 > 0 {
			l = ciphersuite.CCMTagLength8
		}
		cph, err = ciphersuite.NewCCM(newCipherFunc, l, localKey, localIv, remoteKey, remoteIv)
		c.cipher.Store(cph)
	case gcm:
		var cph *ciphersuite.GCM
		cph, err = ciphersuite.NewGCM(newCipherFunc, localKey, localIv, remoteKey, remoteIv)
		c.cipher.Store(cph)
	case cbc:
		var cph *ciphersuite.CBC
		cph, err = ciphersuite.NewCBC(newCipherFunc,
			localKey, localIv, localMacKey,
			remoteKey, remoteIv, remoteMacKey,
			c.HashFunc(),
		)
		c.cipher.Store(cph)
	case nullMode:
		c.cipher.Store(true)
	default:
		return fmt.Errorf("unknown block mode %d", c.spec.mode)
	}
	return err
}

// Encrypt encrypts a single TLS RecordLayer
func (c *SuiteInstance) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cph := c.cipher.Load()
	if cph == nil {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}
	switch c.spec.mode {
	case ccm:
		return cph.(*ciphersuite.CCM).Encrypt(pkt, raw)
	case gcm:
		return cph.(*ciphersuite.GCM).Encrypt(pkt, raw)
	case cbc:
		return cph.(*ciphersuite.CBC).Encrypt(pkt, raw)
	case nullMode:
		return raw, nil
	}
	return nil, fmt.Errorf("unimplemented mode")
}

// Decrypt decrypts a single TLS RecordLayer
func (c *SuiteInstance) Decrypt(raw []byte) ([]byte, error) {
	cph := c.cipher.Load()
	if cph == nil {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	switch c.spec.mode {
	case ccm:
		return cph.(*ciphersuite.CCM).Decrypt(raw)
	case gcm:
		return cph.(*ciphersuite.GCM).Decrypt(raw)
	case cbc:
		return cph.(*ciphersuite.CBC).Decrypt(raw)
	case nullMode:
		return raw, nil
	}
	return nil, fmt.Errorf("unimplemented mode")
}
