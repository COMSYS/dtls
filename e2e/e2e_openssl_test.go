// +build openssl,!js

package e2e

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
)

func serverOpenSSL(c *comm) {
	go func() {
		c.serverMutex.Lock()
		defer c.serverMutex.Unlock()

		cfg := c.serverConfig

		// create openssl arguments
		args := []string{
			"s_server",
			"-dtls1_2",
			"-quiet",
			"-verify_quiet",
			"-verify_return_error",
			"-accept",
		}
		if runtime.GOOS == "windows" {
			args = append(args, fmt.Sprintf("127.0.0.1:%d", c.serverPort))
		} else {
			args = append(args, fmt.Sprintf("%d", c.serverPort))
		}
		ciphers := ciphersOpenSSL(cfg)
		if ciphers != "" {
			args = append(args, "-cipher", ciphers)
		}

		// psk arguments
		if cfg.PSK != nil {
			psk, err := cfg.PSK(nil)
			if err != nil {
				c.errChan <- err
				return
			}
			args = append(args, "-psk", fmt.Sprintf("%X", psk))
			if len(cfg.PSKIdentityHint) > 0 {
				args = append(args, "-psk_hint", fmt.Sprintf("%s", cfg.PSKIdentityHint))
			}
		}

		// certs arguments
		if len(cfg.Certificates) > 0 {
			// create temporary cert files
			certPEM, keyPEM, err := writeTempPEM(cfg)
			if err != nil {
				c.errChan <- err
				return
			}
			args = append(args, "-cert", certPEM, "-key", keyPEM)
			defer func() {
				_ = os.Remove(certPEM)
				_ = os.Remove(keyPEM)
			}()
		} else {
			args = append(args, "-nocert")
		}
		log.Infof("openssl %s", strings.Join(args, " "))

		// launch command
		// #nosec G204
		cmd := exec.CommandContext(c.ctx, "openssl", args...)
		var inner net.Conn
		inner, c.serverConn = net.Pipe()
		cmd.Stdin = inner
		cmd.Stdout = inner
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			c.errChan <- err
			_ = inner.Close()
			return
		}
		defer cmd.Process.Kill()

		// Ensure that server has started
		time.Sleep(500 * time.Millisecond)

		c.serverReady <- struct{}{}
		simpleReadWrite(c.ctx, c.errChan, c.serverChan, c.serverConn, c.messageRecvCount)
	}()
}

func clientOpenSSL(c *comm) {
	select {
	case <-c.serverReady:
		// OK
	case <-time.After(time.Second):
		c.errChan <- errors.New("waiting on serverReady err: timeout")
	}

	c.clientMutex.Lock()
	defer c.clientMutex.Unlock()

	cfg := c.clientConfig

	// create openssl arguments
	args := []string{
		"s_client",
		"-dtls1_2",
		"-quiet",
		"-verify_quiet",
		"-verify_return_error",
		"-servername",
		"localhost",
		"-connect",
	}
	if runtime.GOOS == "windows" {
		args = append(args, fmt.Sprintf("127.0.0.1:%d", c.serverPort))
	} else {
		args = append(args, fmt.Sprintf("%d", c.serverPort))
	}
	ciphers := ciphersOpenSSL(cfg)
	if ciphers != "" {
		args = append(args, "-cipher", ciphers)
	}

	// psk arguments
	if cfg.PSK != nil {
		psk, err := cfg.PSK(nil)
		if err != nil {
			c.errChan <- err
			return
		}
		args = append(args, "-psk", fmt.Sprintf("%X", psk))
	}

	// certificate arguments
	if len(cfg.Certificates) > 0 {
		// create temporary cert files
		certPEM, keyPEM, err := writeTempPEM(cfg)
		if err != nil {
			c.errChan <- err
			return
		}
		args = append(args, "-CAfile", certPEM)
		defer func() {
			_ = os.Remove(certPEM)
			_ = os.Remove(keyPEM)
		}()
	}

	// launch command
	// #nosec G204
	cmd := exec.CommandContext(c.ctx, "openssl", args...)
	var inner net.Conn
	inner, c.clientConn = net.Pipe()
	cmd.Stdin = inner
	cmd.Stdout = inner
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		c.errChan <- err
		_ = inner.Close()
		return
	}

	simpleReadWrite(c.ctx, c.errChan, c.clientChan, c.clientConn, c.messageRecvCount)
}

func ciphersOpenSSL(cfg *dtls.Config) string {
	// See https://tls.mbed.org/supported-ssl-ciphersuites
	translate := map[dtls.CipherSuiteID]string{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:        "ECDHE-ECDSA-AES128-CCM",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:      "ECDHE-ECDSA-AES128-CCM8",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "ECDHE-ECDSA-AES128-GCM-SHA256",
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "ECDHE-RSA-AES128-GCM-SHA256",

		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: "ECDHE-ECDSA-AES256-SHA",
		dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:   "ECDHE-RSA-AES256-SHA",

		dtls.TLS_PSK_WITH_AES_128_CCM:        "PSK-AES128-CCM",
		dtls.TLS_PSK_WITH_AES_128_CCM_8:      "PSK-AES128-CCM8",
		dtls.TLS_PSK_WITH_AES_128_GCM_SHA256: "PSK-AES128-GCM-SHA256",
		// Added Johannes
		dtls.TLS_RSA_WITH_NULL_MD5:                   "NULL-MD5",
		dtls.TLS_RSA_WITH_NULL_SHA:                   "NULL-SHA",
		dtls.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:      "EXP-RC2-CBC-MD5",
		dtls.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:       "EXP-DES-CBC-SHA",
		dtls.TLS_RSA_WITH_DES_CBC_SHA:                "DES-CBC-SHA",
		dtls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "DES-CBC3-SHA",
		dtls.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:    "EXP-DH-DSS-DES-CBC-SHA",
		dtls.TLS_DH_DSS_WITH_DES_CBC_SHA:             "DH-DSS-DES-CBC-SHA",
		dtls.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:    "EXP-DH-RSA-DES-CBC-SHA",
		dtls.TLS_DH_RSA_WITH_DES_CBC_SHA:             "DH-RSA-DES-CBC-SHA",
		dtls.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:   "EXP-EDH-DSS-DES-CBC-SHA",
		dtls.TLS_DHE_DSS_WITH_DES_CBC_SHA:            "EDH-DSS-DES-CBC-SHA",
		dtls.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:   "EXP-EDH-RSA-DES-CBC-SHA",
		dtls.TLS_DHE_RSA_WITH_DES_CBC_SHA:            "EDH-RSA-DES-CBC-SHA",
		dtls.TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA:   "EXP-ADH-DES-CBC-SHA",
		dtls.TLS_DH_ANON_WITH_DES_CBC_SHA:            "ADH-DES-CBC-SHA",
		dtls.TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA:       "ADH-DES-CBC3-SHA",
		dtls.TLS_RSA_WITH_AES_128_CBC_SHA:            "AES128-SHA",
		dtls.TLS_RSA_WITH_AES_256_CBC_SHA:            "AES256-SHA",
		dtls.TLS_RSA_WITH_NULL_SHA256:                "NULL-SHA256",
		dtls.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:      "DH-DSS-AES128-SHA256",
		dtls.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:      "DH-RSA-AES128-SHA256",
		dtls.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:     "DHE-DSS-AES128-SHA256",
		dtls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:     "DHE-RSA-AES128-SHA256",
		dtls.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:      "DH-DSS-AES256-SHA256",
		dtls.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:      "DH-RSA-AES256-SHA256",
		dtls.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:     "DHE-DSS-AES256-SHA256",
		dtls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:     "DHE-RSA-AES256-SHA256",
		dtls.TLS_DH_ANON_WITH_AES_128_CBC_SHA256:     "ADH-AES128-SHA256",
		dtls.TLS_DH_ANON_WITH_AES_256_CBC_SHA256:     "ADH-AES256-SHA256",
		dtls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:     "DHE-RSA-AES128-GCM-SHA256",
		dtls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:     "DH-RSA-AES128-GCM-SHA256",
		dtls.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:      "DH-RSA-AES128-GCM-SHA256",
		dtls.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:      "DH-RSA-AES256-GCM-SHA384",
		dtls.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:     "DHE-DSS-AES128-GCM-SHA256",
		dtls.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:     "DHE-DSS-AES256-GCM-SHA384",
		dtls.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:      "DH-DSS-AES128-GCM-SHA256",
		dtls.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:      "DH-DSS-AES256-GCM-SHA384",
		dtls.TLS_DH_ANON_WITH_AES_128_GCM_SHA256:     "ADH-AES128-GCM-SHA256",
		dtls.TLS_DH_ANON_WITH_AES_256_GCM_SHA384:     "ADH-AES256-GCM-SHA384",
		dtls.TLS_ECDH_ECDSA_WITH_NULL_SHA:            "ECDH-ECDSA-NULL-SHA",
		dtls.TLS_ECDHE_ECDSA_WITH_NULL_SHA:           "ECDHE-ECDSA-NULL-SHA",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "ECDHE-ECDSA-AES128-SHA",
		dtls.TLS_ECDH_RSA_WITH_NULL_SHA:              "ECDH-RSA-NULL-SHA",
		dtls.TLS_ECDHE_RSA_WITH_NULL_SHA:             "ECDHE-RSA-NULL-SHA",
		dtls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "ECDHE-RSA-DES-CBC3-SHA",
		dtls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "ECDHE-RSA-AES128-SHA",
		dtls.TLS_ECDH_ANON_WITH_NULL_SHA:             "AECDH-NULL-SHA",
		dtls.TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA:     "AECDH-DES-CBC3-SHA",
		dtls.TLS_ECDH_ANON_WITH_AES_128_CBC_SHA:      "AECDH-AES128-SHA",
		dtls.TLS_ECDH_ANON_WITH_AES_256_CBC_SHA:      "AECDH-AES256-SHA",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "ECDHE-ECDSA-AES128-SHA256",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: "ECDHE-ECDSA-AES256-SHA384",
		dtls.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:  "ECDH-ECDSA-AES128-SHA256",
		dtls.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:  "ECDH-ECDSA-AES256-SHA384",
		dtls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "ECDHE-RSA-AES128-SHA256",
		dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:   "ECDHE-RSA-AES256-SHA384",
		dtls.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:    "ECDH-RSA-AES128-SHA256",
		dtls.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:    "ECDH-RSA-AES256-SHA384",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "ECDHE-ECDSA-AES256-GCM-SHA384",
		dtls.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:  "ECDH-ECDSA-AES128-GCM-SHA256",
		dtls.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:  "ECDH-ECDSA-AES256-GCM-SHA384",
		dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "ECDHE-RSA-AES256-GCM-SHA384",
		dtls.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:    "ECDH-RSA-AES128-GCM-SHA256",
		dtls.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:    "ECDH-RSA-AES256-GCM-SHA384",
		dtls.TLS_DHE_RSA_WITH_AES_128_CCM:            "DHE-RSA-AES128-CCM",
		dtls.TLS_DHE_RSA_WITH_AES_256_CCM:            "DHE-RSA-AES256-CCM",
		dtls.TLS_DHE_RSA_WITH_AES_128_CCM_8:          "DHE-RSA-AES128-CCM8",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:        "ECDHE-ECDSA-AES256-CCM",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:      "ECDHE-ECDSA-AES256-CCM8",
	}

	var ciphers []string
	for _, c := range cfg.CipherSuites {
		if text, ok := translate[c]; ok {
			ciphers = append(ciphers, text)
		}
	}
	return strings.Join(ciphers, ";")
}

func TestPionOpenSSLE2ESimple(t *testing.T) {
	tcs := []testCase{
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, "ecdsa"},
		{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ecdsa"},
		{dtls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "rsa"},
		{dtls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "rsa"},
		{dtls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "rsa"},
		{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "rsa"},
		{dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "rsa"},
		{dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "rsa"},
		{dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "rsa"},
		{dtls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "rsa"},
		{dtls.TLS_RSA_WITH_AES_128_CBC_SHA, "rsa"},
		{dtls.TLS_RSA_WITH_AES_256_CBC_SHA, "rsa"},
	}
	t.Run("OpenSSLServer", func(t *testing.T) {
		testPionE2ESimple(t, serverOpenSSL, clientPion, tcs)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2ESimple(t, serverPion, clientOpenSSL, tcs)
	})
}

func TestPionOpenSSLE2ESimplePSK(t *testing.T) {
	t.Run("OpenSSLServer", func(t *testing.T) {
		testPionE2ESimplePSK(t, serverOpenSSL, clientPion)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2ESimplePSK(t, serverPion, clientOpenSSL)
	})
}

func TestPionOpenSSLE2EMTUs(t *testing.T) {
	t.Run("OpenSSLServer", func(t *testing.T) {
		testPionE2EMTUs(t, serverOpenSSL, clientPion)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2EMTUs(t, serverPion, clientOpenSSL)
	})
}
