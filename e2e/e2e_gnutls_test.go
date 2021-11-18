// +build gnutls,!js

package e2e

/*
func TestManual(t *testing.T) {
	log.SetLevel(log.TraceLevel)

	for _, tc := range []struct {
		suite dtls.CipherSuiteID
		cert  string
	}{
		{dtls.TLS_RSA_WITH_NULL_SHA, "rsa"},
	} {

		t.Run(tc.suite.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			cfg := &dtls.Config{
				CipherSuites:       []dtls.CipherSuiteID{tc.suite},
				InsecureSkipVerify: true,
			}

			var err error
			clientConn, err := dtls.DialWithContext(ctx, "udp",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000},
				cfg,
			)
			if err != nil {
				t.Fatal(err)
			}

			clientConn.Write([]byte("hello world"))
		})
	}

}
*/
