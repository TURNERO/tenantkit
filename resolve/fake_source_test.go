package resolve_test

import "crypto/x509"

type fakeSource struct {
	headers map[string]string
	certs   []*x509.Certificate
	host    string
}

func (s fakeSource) Header(key string) string                 { return s.headers[key] }
func (s fakeSource) TLSPeerCertificates() []*x509.Certificate { return s.certs }
func (s fakeSource) Host() string                             { return s.host }
