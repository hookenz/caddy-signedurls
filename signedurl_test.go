package signedurl

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"go.uber.org/zap"
)

// Helper function to create a signature
func createSignature(secret, data string) string {
	return createSignatureWithAlgorithm(secret, data, sha256.New)
}

// Helper function to create a signature with specific algorithm
func createSignatureWithAlgorithm(secret, data string, hashFunc func() hash.Hash) string {
	h := hmac.New(hashFunc, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Mock next handler that returns 200 OK
type mockHandler struct{}

func (m mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("success"))
	return nil
}

// Setup helper
func setupHandler(secret string) *SignedURL {
	return setupHandlerWithAlgorithm(secret, "sha256")
}

// Setup helper with algorithm
func setupHandlerWithAlgorithm(secret, algorithm string) *SignedURL {
	s := &SignedURL{
		Secret:    secret,
		Algorithm: algorithm,
		logger:    zap.NewNop(), // Use no-op logger for tests
	}

	// Set hash function based on algorithm
	switch algorithm {
	case "sha256":
		s.hashFunc = sha256.New
	case "sha384":
		s.hashFunc = sha512.New384
	case "sha512":
		s.hashFunc = sha512.New
	}

	// Set defaults manually since we're skipping full Provision
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
	return s
}

func TestSignedURL_ValidSignature(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"
	signature := createSignature(secret, path)

	req := httptest.NewRequest("GET", path+"?signature="+signature, nil)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestSignedURL_InvalidSignature(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"

	req := httptest.NewRequest("GET", path+"?signature=invalid", nil)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestSignedURL_MissingSignature(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	req := httptest.NewRequest("GET", "/test/file.pdf", nil)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestSignedURL_SignatureInHeader(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"
	signature := createSignature(secret, path)

	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("X-Signature", signature)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestSignedURL_WithExpires_NotExpired(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"
	expires := time.Now().Unix() + 3600 // 1 hour from now

	toSign := fmt.Sprintf("%s?expires=%d", path, expires)
	signature := createSignature(secret, toSign)

	reqURL := fmt.Sprintf("%s?expires=%d&signature=%s", path, expires, signature)
	req := httptest.NewRequest("GET", reqURL, nil)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestSignedURL_WithExpires_Expired(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"
	expires := time.Now().Unix() - 3600 // 1 hour ago

	toSign := fmt.Sprintf("%s?expires=%d", path, expires)
	signature := createSignature(secret, toSign)

	reqURL := fmt.Sprintf("%s?expires=%d&signature=%s", path, expires, signature)
	req := httptest.NewRequest("GET", reqURL, nil)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}

	body := w.Body.String()
	if body != "URL has expired\n" {
		t.Errorf("expected 'URL has expired' message, got %s", body)
	}
}

func TestSignedURL_WithIssued(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"
	issued := time.Now().Unix() - 60 // 1 minute ago
	expires := time.Now().Unix() + 3600

	// Build query with sorted params
	query := url.Values{}
	query.Set("expires", fmt.Sprintf("%d", expires))
	query.Set("issued", fmt.Sprintf("%d", issued))

	toSign := path + "?" + query.Encode()
	signature := createSignature(secret, toSign)

	query.Set("signature", signature)
	reqURL := path + "?" + query.Encode()

	req := httptest.NewRequest("GET", reqURL, nil)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestSignedURL_QueryParamOrdering(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"
	issued := time.Now().Unix()
	expires := time.Now().Unix() + 3600

	// Create signature with sorted params
	query := url.Values{}
	query.Set("expires", fmt.Sprintf("%d", expires))
	query.Set("issued", fmt.Sprintf("%d", issued))
	query.Set("foo", "bar")

	toSign := path + "?" + query.Encode()
	signature := createSignature(secret, toSign)

	// Test multiple different orderings - all should work
	testCases := []string{
		fmt.Sprintf("%s?expires=%d&issued=%d&foo=bar&signature=%s", path, expires, issued, signature),
		fmt.Sprintf("%s?issued=%d&expires=%d&foo=bar&signature=%s", path, issued, expires, signature),
		fmt.Sprintf("%s?foo=bar&expires=%d&issued=%d&signature=%s", path, expires, issued, signature),
		fmt.Sprintf("%s?signature=%s&foo=bar&issued=%d&expires=%d", path, signature, issued, expires),
	}

	for i, testURL := range testCases {
		t.Run(fmt.Sprintf("ordering_%d", i), func(t *testing.T) {
			req := httptest.NewRequest("GET", testURL, nil)
			w := httptest.NewRecorder()

			err := handler.ServeHTTP(w, req, mockHandler{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if w.Code != http.StatusOK {
				t.Errorf("expected status 200 for URL %s, got %d: %s", testURL, w.Code, w.Body.String())
			}
		})
	}
}

func TestSignedURL_InvalidExpiresFormat(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"

	req := httptest.NewRequest("GET", path+"?expires=invalid&signature=test", nil)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestSignedURL_InvalidIssuedFormat(t *testing.T) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"

	req := httptest.NewRequest("GET", path+"?issued=invalid&signature=test", nil)
	w := httptest.NewRecorder()

	err := handler.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestSignedURL_CustomParamNames(t *testing.T) {
	s := &SignedURL{
		Secret:       "test-secret",
		QueryParam:   "sig",
		ExpiresParam: "exp",
		IssuedParam:  "iat",
		Header:       "X-Signature",
		logger:       zap.NewNop(),
	}

	path := "/test/file.pdf"
	expires := time.Now().Unix() + 3600

	query := url.Values{}
	query.Set("exp", fmt.Sprintf("%d", expires))

	toSign := path + "?" + query.Encode()
	signature := createSignature(s.Secret, toSign)

	query.Set("sig", signature)
	reqURL := path + "?" + query.Encode()

	req := httptest.NewRequest("GET", reqURL, nil)
	w := httptest.NewRecorder()

	err := s.ServeHTTP(w, req, mockHandler{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func BenchmarkSignedURL_ValidSignature(b *testing.B) {
	secret := "test-secret"
	handler := setupHandler(secret)

	path := "/test/file.pdf"
	signature := createSignature(secret, path)

	req := httptest.NewRequest("GET", path+"?signature="+signature, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req, mockHandler{})
	}
}
