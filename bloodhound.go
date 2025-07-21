package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	ListenAddr string `env:"ListenAddr" envDefault:"0.0.0.0:25663"`
	BoneFolder string `env:"BoneFolder" envDEfault:""`
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

	sp := &SniffingProxy{
		target: url,
		proxy:  proxy,
	}

	// Customize the proxy to add Sniffing
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
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
	filename := filepath.Join(cfg.BoneFolder, fmt.Sprintf("%d-request.txt", reqID))

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
		log.Error().Int64("id", reqID).Msgf("ERROR writing request file %0d-request.txt : %v", reqID, err)
	}
}

func (sp *SniffingProxy) writeResponseToFile(resp *http.Response, reqID int64) {
	filename := filepath.Join(cfg.BoneFolder, fmt.Sprintf("%d-response.txt", reqID))

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
		log.Error().Int64("id", reqID).Msgf("ERROR writing response file %0d-response.txt : %v", reqID, err)
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
	log.Info().Str("phase", "completed").Str("method", r.Method).Str("url", r.URL.Path).Int("statusCode", wrappedWriter.statusCode).Dur("duration", duration).Int64("id", reqID).Msg("Completed")
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

func main() {
	var err error
	cfg, err = env.ParseAs[Config]()
	if err != nil {
		log.Fatal().Msgf("error reading ENV config: %v", err)
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

	log.Warn().Msgf("starting reverse proxy on %s, proxying to %s", cfg.ListenAddr, cfg.TargetUrl)
	if len(cfg.BoneFolder) > 0 {
		log.Warn().Msgf("sniffed bones will be written to %s", cfg.BoneFolder)

	}
	// Start the server
	if err := server.ListenAndServe(); err != nil {
		log.Fatal().Msgf("Server failed to start: %v", err)
	}
}
