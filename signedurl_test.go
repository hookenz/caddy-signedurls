package signedurl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SignedURL{})
	httpcaddyfile.RegisterHandlerDirective("signed_url", parseCaddyfile)
}

// SignedURL implements an HTTP handler that validates HMAC signatures
type SignedURL struct {
	// Secret key for HMAC signing
	Secret string `json:"secret,omitempty"`

	// Algorithm is the hash algorithm to use (default: "sha256")
	// Supported: sha256, sha384, sha512
	Algorithm string `json:"algorithm,omitempty"`

	// QueryParam is the query parameter name for the signature (default: "signature")
	QueryParam string `json:"query_param,omitempty"`

	// Header is the HTTP header name for the signature (default: "X-Signature")
	Header string `json:"header,omitempty"`

	// ExpiresParam is the query parameter name for expiration timestamp (default: "expires")
	ExpiresParam string `json:"expires_param,omitempty"`

	// IssuedParam is the query parameter name for issued/generated timestamp (default: "issued")
	IssuedParam string `json:"issued_param,omitempty"`

	logger   *zap.Logger
	hashFunc func() hash.Hash
}

// CaddyModule returns the Caddy module information
func (SignedURL) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.signed_url",
		New: func() caddy.Module { return new(SignedURL) },
	}
}

// Provision implements caddy.Provisioner
func (s *SignedURL) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger(s)

	if s.Secret == "" {
		return fmt.Errorf("secret is required for signed URL")
	}

	// Set defaults
	if s.QueryParam == "" {
		s.QueryParam = "signature"
	}
	if s.Header == "" {
		s.Header = "X-Signature"
	}
	if s.ExpiresParam == "" {
		s.ExpiresParam = "expires"
	}
	if s.IssuedParam == "" {
		s.IssuedParam = "issued"
	}

	s.logger.Info("signed_url handler provisioned",
		zap.String("query_param", s.QueryParam),
		zap.String("header", s.Header),
		zap.String("expires_param", s.ExpiresParam),
		zap.String("issued_param", s.IssuedParam),
	)

	return nil
}

// Validate implements caddy.Validator
func (s *SignedURL) Validate() error {
	if s.Secret == "" {
		return fmt.Errorf("secret cannot be empty")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler
func (s SignedURL) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract signature from query param or header
	signature := r.URL.Query().Get(s.QueryParam)
	signatureSource := "query"
	if signature == "" {
		signature = r.Header.Get(s.Header)
		signatureSource = "header"
	}

	if signature == "" {
		s.logger.Warn("missing signature",
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
		)
		http.Error(w, "Missing signature", http.StatusUnauthorized)
		return nil
	}

	now := time.Now().Unix()

	// Parse issued timestamp if present (for logging/audit purposes only)
	var issuedAt int64
	issuedStr := r.URL.Query().Get(s.IssuedParam)
	if issuedStr != "" {
		var err error
		issuedAt, err = strconv.ParseInt(issuedStr, 10, 64)
		if err != nil {
			s.logger.Warn("invalid issued parameter",
				zap.String("path", r.URL.Path),
				zap.String("issued", issuedStr),
				zap.Error(err),
			)
			http.Error(w, "Invalid issued parameter", http.StatusBadRequest)
			return nil
		}
	}

	// Check expiration timestamp if present
	expiresStr := r.URL.Query().Get(s.ExpiresParam)
	if expiresStr != "" {
		expiresAt, err := strconv.ParseInt(expiresStr, 10, 64)
		if err != nil {
			s.logger.Warn("invalid expires parameter",
				zap.String("path", r.URL.Path),
				zap.String("expires", expiresStr),
				zap.Error(err),
			)
			http.Error(w, "Invalid expires parameter", http.StatusBadRequest)
			return nil
		}

		// Check if URL has expired
		if now > expiresAt {
			s.logger.Warn("url expired",
				zap.String("path", r.URL.Path),
				zap.Int64("expired_at", expiresAt),
				zap.Int64("current_time", now),
				zap.Int64("expired_by", now-expiresAt),
			)
			http.Error(w, "URL has expired", http.StatusUnauthorized)
			return nil
		}
	}

	// Build the string to sign (full path including query params minus the signature)
	// Query parameters are sorted to ensure consistent ordering
	query := r.URL.Query()
	query.Del(s.QueryParam)

	var toSign string
	if len(query) > 0 {
		// Encode() automatically sorts keys alphabetically for consistent signatures
		toSign = r.URL.Path + "?" + query.Encode()
	} else {
		toSign = r.URL.Path
	}

	// Calculate expected signature
	expectedSig := s.calculateSignature(toSign)

	// Compare signatures (constant time comparison)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		s.logger.Warn("invalid signature",
			zap.String("path", r.URL.Path),
			zap.String("signature_source", signatureSource),
			zap.String("remote_addr", r.RemoteAddr),
		)
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return nil
	}

	// Signature is valid, continue to next handler
	logFields := []zap.Field{
		zap.String("path", r.URL.Path),
		zap.String("signature_source", signatureSource),
	}
	if issuedAt > 0 {
		logFields = append(logFields,
			zap.Int64("issued_at", issuedAt),
			zap.Int64("age_seconds", now-issuedAt),
		)
	}
	if expiresStr != "" {
		expiresAt, _ := strconv.ParseInt(expiresStr, 10, 64)
		logFields = append(logFields,
			zap.Int64("expires_at", expiresAt),
			zap.Int64("ttl_seconds", expiresAt-now),
		)
	}
	s.logger.Debug("signature validated successfully", logFields...)

	return next.ServeHTTP(w, r)
}

// calculateSignature generates HMAC-SHA256 signature
func (s *SignedURL) calculateSignature(data string) string {
	h := hmac.New(sha256.New, []byte(s.Secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (s *SignedURL) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Check for inline secret: signed_url "value"
		if d.NextArg() {
			s.Secret = d.Val()
			// No more args expected in inline form
			if d.NextArg() {
				return d.ArgErr()
			}
			continue
		}

		// Block form: signed_url { ... }
		for d.NextBlock(0) {
			switch d.Val() {
			case "secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.Secret = d.Val()

			case "query_param":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.QueryParam = d.Val()

			case "header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.Header = d.Val()

			case "expires_param":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.ExpiresParam = d.Val()

			case "issued_param":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.IssuedParam = d.Val()

			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var s SignedURL
	err := s.UnmarshalCaddyfile(h.Dispenser)
	return s, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*SignedURL)(nil)
	_ caddy.Validator             = (*SignedURL)(nil)
	_ caddyhttp.MiddlewareHandler = (*SignedURL)(nil)
	_ caddyfile.Unmarshaler       = (*SignedURL)(nil)
)
