package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSource_Header(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Tenant-ID", "acme")
	src := httpSource{r: r}

	if got := src.Header("X-Tenant-ID"); got != "acme" {
		t.Errorf("Header(X-Tenant-ID) = %q, want acme", got)
	}
}

func TestHTTPSource_TLSPeerCertificatesNilWithoutTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	src := httpSource{r: r}

	if got := src.TLSPeerCertificates(); got != nil {
		t.Errorf("TLSPeerCertificates() = %v, want nil for a non-TLS request", got)
	}
}

func TestHTTPSource_HostStripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "acme.example.com:8080"
	src := httpSource{r: r}

	if got := src.Host(); got != "acme.example.com" {
		t.Errorf("Host() = %q, want acme.example.com", got)
	}
}

func TestHTTPSource_HostWithoutPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "acme.example.com"
	src := httpSource{r: r}

	if got := src.Host(); got != "acme.example.com" {
		t.Errorf("Host() = %q, want acme.example.com", got)
	}
}
