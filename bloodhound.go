package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/rs/zerolog/log"
)

type Config struct {
	TargetUrl  string `env:"TargetUrl" envDefault:"https://httpbin.org"`
	ListenAddr string `env:"ListenAddr"`
	BoneFolder string `env:"BoneFolder" envDefault:""`

	// Inbound TLS (clients -> bloodhound)
	TlsCert     string   `env:"TlsCert" envDefault:""`
	TlsKey      string   `env:"TlsKey" envDefault:""`
	TlsAutoCert bool     `env:"TlsAutoCert" envDefault:"false"`
	TlsHosts    []string `env:"TlsHosts" envSeparator:"," envDefault:"localhost,127.0.0.1,::1"`

	// Outbound TLS (bloodhound -> TargetUrl)
	TargetInsecure bool   `env:"TargetInsecure" envDefault:"false"`
	TargetCaCert   string `env:"TargetCaCert" envDefault:""`
}

var cfg Config
var requestIdCounter int64

const requestIDKey = "requestID"

type SniffingProxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func NewSniffingProxy(target string) (*SniffingProxy, error) {
	url, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(url)

	transport, err := newTransport()
	if err != nil {
		return nil, err
	}
	proxy.Transport = transport

	sp := &SniffingProxy{
		target: url,
		proxy:  proxy,
	}

	// Customize the proxy to add Sniffing
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// NewSingleHostReverseProxy rewrites req.URL but leaves req.Host as the
		// client sent it, which misroutes vhosted upstreams. Send the target host.
		req.Host = sp.target.Host
		if reqID := req.Context().Value(requestIDKey); reqID != nil {
			sp.sniffRequest(req, reqID.(int64))
			if len(cfg.BoneFolder) > 0 {
				sp.writeRequestToFile(req, reqID.(int64))
			}
		}
	}

	// Add response Sniffing
	proxy.ModifyResponse = func(resp *http.Response) error {
		if reqID := resp.Request.Context().Value(requestIDKey); reqID != nil {
			sp.sniffResponse(resp, reqID.(int64))
			if len(cfg.BoneFolder) > 0 {
				sp.writeResponseToFile(resp, reqID.(int64))
			}
		}
		return nil
	}

	return sp, nil
}

func (sp *SniffingProxy) sniffRequest(req *http.Request, reqID int64) {
	log.Info().Str("phase", "request").Str("method", req.Method).Str("url", req.URL.Path).Str("proto", req.Proto).Str("userAgent", req.UserAgent()).Str("remoteAddr", req.RemoteAddr).Int64("id", reqID).Msg("Request")
}

func (sp *SniffingProxy) sniffResponse(resp *http.Response, reqID int64) error {
	log.Info().Str("phase", "response").Str("method", resp.Request.Method).Str("url", resp.Request.URL.Path).Int("statusCode", resp.StatusCode).Str("status", resp.Status).Str("contentLength", resp.Header.Get("Content-Length")).Int64("id", reqID).Msg("Response")
	return nil
}

func (sp *SniffingProxy) writeRequestToFile(req *http.Request, reqID int64) {
	dt := time.Now()
	filename := filepath.Join(cfg.BoneFolder, fmt.Sprintf("%s-%06d-request.txt", dt.Format("20060102-150405"), reqID))

	// Create a buffer to capture the request dump
	var buf bytes.Buffer

	// Write request line and headers
	fmt.Fprintf(&buf, "%s %s %s\n", req.Method, req.RequestURI, req.Proto)
	fmt.Fprintf(&buf, "Host: %s\n", req.Host)

	// Write all headers
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Fprintf(&buf, "%s: %s\n", name, value)
		}
	}

	fmt.Fprintf(&buf, "\n") // Empty line between headers and body

	// Read and write body if present
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			buf.Write(bodyBytes)
			// Restore the body for the actual request
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// Write to file
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		log.Error().Int64("id", reqID).Msgf("ERROR writing request file : %v", err)
	}
}

func (sp *SniffingProxy) writeResponseToFile(resp *http.Response, reqID int64) {
	dt := time.Now()
	filename := filepath.Join(cfg.BoneFolder, fmt.Sprintf("%s-%06d-response.txt", dt.Format("20060102-150405"), reqID))

	// Create a buffer to capture the response dump
	var buf bytes.Buffer

	// Write status line
	fmt.Fprintf(&buf, "%s %s\n", resp.Proto, resp.Status)

	// Write all headers
	for name, values := range resp.Header {
		for _, value := range values {
			fmt.Fprintf(&buf, "%s: %s\n", name, value)
		}
	}

	fmt.Fprintf(&buf, "\n") // Empty line between headers and body

	// Read and write body if present
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			buf.Write(bodyBytes)
			// Restore the body for the client
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// Write to file
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		log.Error().Int64("id", reqID).Msgf("ERROR writing response file : %v", err)
	}
}

func (sp *SniffingProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := atomic.AddInt64(&requestIdCounter, 1)

	// Add reqID to context
	ctx := context.WithValue(r.Context(), requestIDKey, reqID)
	r = r.WithContext(ctx)

	// Wrap the response writer to capture status code
	wrappedWriter := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	sp.proxy.ServeHTTP(wrappedWriter, r)

	duration := time.Since(start)
	tlsVersion, tlsServerName := "", ""
	if r.TLS != nil {
		tlsVersion = tls.VersionName(r.TLS.Version)
		tlsServerName = r.TLS.ServerName
	}
	log.Info().Str("phase", "completed").Str("method", r.Method).Str("url", r.URL.Path).Int("statusCode", wrappedWriter.statusCode).Dur("duration", duration).Str("tlsVersion", tlsVersion).Str("tlsServerName", tlsServerName).Int64("id", reqID).Msg("Completed")
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// newTransport builds the upstream (bloodhound -> TargetUrl) transport. It
// mirrors http.DefaultTransport so we keep its connection pooling, and adds the
// TLS knobs needed to sniff targets using a private CA or a self-signed cert.
func newTransport() (*http.Transport, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TargetInsecure,
	}

	if len(cfg.TargetCaCert) > 0 {
		pemBytes, err := os.ReadFile(cfg.TargetCaCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read TargetCaCert %s: %w", cfg.TargetCaCert, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates found in TargetCaCert %s", cfg.TargetCaCert)
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
		Proxy:             http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}, nil
}

// generateSelfSignedCert mints an in-memory, self-signed server certificate for
// the given hosts. Used when TlsAutoCert is set and no TlsCert/TlsKey is given;
// clients will need to skip verification (curl -k) or pin the fingerprint.
func generateSelfSignedCert(hosts []string) (tls.Certificate, error) {
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"bloodhound"}, CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	fingerprint := sha256.Sum256(der)
	log.Warn().Msgf("generated self-signed certificate for %v, sha256 fingerprint %s", hosts, hex.EncodeToString(fingerprint[:]))

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

const usageText = `bloodhound - HTTP reverse proxy sniffer

Usage:
  bloodhound          Run the proxy. Configuration is via environment variables.
  bloodhound -h       Show this help.

Required environment variables:
  ListenAddr          Address to listen on, as addr:port (e.g. 127.0.0.1:25663)
  TargetUrl           URL to proxy to (default https://httpbin.org)

Sniffing:
  BoneFolder          Folder to write raw request/response files to
                      (default empty, which disables writing them)

Inbound TLS (clients -> bloodhound):
  TlsCert             PEM certificate (chain) to serve HTTPS with
  TlsKey              PEM private key matching TlsCert
  TlsAutoCert         Serve HTTPS with a self-signed cert generated at startup
                      (default false)
  TlsHosts            Comma separated SANs for the TlsAutoCert certificate
                      (default localhost,127.0.0.1,::1)

Outbound TLS (bloodhound -> TargetUrl):
  TargetInsecure      Do not verify the target's TLS certificate (default false)
  TargetCaCert        Extra CA bundle used to verify the target's certificate

Example:
  ListenAddr=127.0.0.1:25663 TargetUrl=https://httpbin.org BoneFolder=./bones bloodhound

See README.md for how to run your own CA and how to trust it on clients.
`

func usage() {
	fmt.Fprint(os.Stderr, usageText)
}

// parseArgs handles -h. Everything else is configured through the environment,
// so any other argument is a mistake worth stopping on.
func parseArgs() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-h", "-help", "--help":
			usage()
			os.Exit(0)
		default:
			usage()
			log.Fatal().Msgf("unknown argument %q, bloodhound is configured through environment variables", arg)
		}
	}
}

// validateConfig checks the required parameters are present and usable, so we
// fail with an explanation at startup rather than a confusing error per request.
func validateConfig() error {
	if len(cfg.ListenAddr) == 0 {
		return fmt.Errorf("ListenAddr is required, e.g. ListenAddr=127.0.0.1:25663")
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		return fmt.Errorf("ListenAddr %q must be addr:port, e.g. 127.0.0.1:25663", cfg.ListenAddr)
	}

	if len(cfg.TargetUrl) == 0 {
		return fmt.Errorf("TargetUrl is required, e.g. TargetUrl=https://httpbin.org")
	}
	target, err := url.Parse(cfg.TargetUrl)
	if err != nil {
		return fmt.Errorf("TargetUrl %q is not a valid URL: %w", cfg.TargetUrl, err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("TargetUrl %q must start with http:// or https://", cfg.TargetUrl)
	}
	if len(target.Host) == 0 {
		return fmt.Errorf("TargetUrl %q is missing a host", cfg.TargetUrl)
	}

	if (len(cfg.TlsCert) > 0) != (len(cfg.TlsKey) > 0) {
		return fmt.Errorf("TlsCert and TlsKey must both be set, or both be empty")
	}

	return nil
}

func main() {
	parseArgs()

	var err error
	cfg, err = env.ParseAs[Config]()
	if err != nil {
		usage()
		log.Fatal().Msgf("error reading ENV config: %v", err)
	}

	if err := validateConfig(); err != nil {
		usage()
		log.Fatal().Msgf("%v", err)
	}

	// Create the Sniffing proxy
	proxy, err := NewSniffingProxy(cfg.TargetUrl)
	if err != nil {
		log.Fatal().Msgf("failed to create proxy: %v", err)
	}

	// Create HTTP server
	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: proxy,
	}

	// Inbound TLS: an explicit keypair wins, otherwise TlsAutoCert generates one
	useTls := false
	switch {
	case len(cfg.TlsCert) > 0:
		// validateConfig has already checked TlsKey is set alongside it
		useTls = true
	case cfg.TlsAutoCert:
		cert, err := generateSelfSignedCert(cfg.TlsHosts)
		if err != nil {
			log.Fatal().Msgf("failed to generate self-signed certificate: %v", err)
		}
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		useTls = true
	}

	scheme := "http"
	if useTls {
		scheme = "https"
	}
	log.Warn().Msgf("starting reverse proxy on %s://%s, proxying to %s", scheme, cfg.ListenAddr, cfg.TargetUrl)
	if len(cfg.BoneFolder) > 0 {
		log.Warn().Msgf("sniffed bones will be written to %s", cfg.BoneFolder)

	}
	if cfg.TargetInsecure {
		log.Warn().Msg("TargetInsecure is set, upstream TLS certificates will NOT be verified")
	}
	if len(cfg.TargetCaCert) > 0 {
		log.Warn().Msgf("upstream TLS certificates will also be verified against %s", cfg.TargetCaCert)
	}

	// Start the server
	if useTls {
		// Empty strings make ListenAndServeTLS use server.TLSConfig.Certificates
		err = server.ListenAndServeTLS(cfg.TlsCert, cfg.TlsKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatal().Msgf("Server failed to start: %v", err)
	}
}
