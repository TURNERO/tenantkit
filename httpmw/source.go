package httpmw

import (
	"crypto/x509"
	"net"
	"net/http"

	"github.com/TURNERO/tenantkit/resolve"
)

type httpSource struct {
	r *http.Request
}

func (s httpSource) Header(key string) string {
	return s.r.Header.Get(key)
}

func (s httpSource) TLSPeerCertificates() []*x509.Certificate {
	if s.r.TLS == nil {
		return nil
	}
	return s.r.TLS.PeerCertificates
}

func (s httpSource) Host() string {
	host := s.r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

var _ resolve.Source = httpSource{}
