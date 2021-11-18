// Package ciphersuite provides TLS Ciphers as registered with the IANA  https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
package cipherspec

import (
	"errors"
	"github.com/pion/dtls/v2/pkg/protocol"
)

var errCipherSuiteNotInit = &protocol.TemporaryError{Err: errors.New("CipherSuite has not been initialized")} //nolint:goerr113

// AuthenticationType controls what authentication method is using during the handshake
type AuthenticationType int

// AuthenticationType Enums
const (
	AuthenticationTypeCertificate AuthenticationType = iota + 1
	AuthenticationTypePreSharedKey
	AuthenticationTypeAnonymous
)
