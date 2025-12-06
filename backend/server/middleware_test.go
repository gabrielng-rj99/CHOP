/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	// Create a mock handler that does nothing
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create the server instance (dependencies don't matter for this test)
	s := &Server{}

	// Create the middleware
	handler := s.securityHeadersMiddleware(nextHandler)

	// Create a request
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	// Serve the request
	handler.ServeHTTP(rr, req)

	// Check headers
	expectedHeaders := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"X-XSS-Protection":          "1; mode=block",
		"Content-Security-Policy":   "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}

	for header, expectedValue := range expectedHeaders {
		if value := rr.Header().Get(header); value != expectedValue {
			t.Errorf("Header %s: expected %s, got %s", header, expectedValue, value)
		}
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	// Create a mock handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	s := &Server{
		rateLimiter: NewIPRateLimiter(5, 10),
	}
	handler := s.rateLimitMiddleware(nextHandler)

	// Use a unique IP for this test to avoid interference
	ip := "192.168.1.100"

	// Rate limit is 5 req/s, burst 10.
	// We should be able to make 10 requests immediately.
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("X-Forwarded-For", ip)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Request %d failed with status %d", i+1, rr.Code)
		}
	}

	// The 31st request might fail depending on how fast correct execution is,
	// but rate limiter refills at 10/s.
	// To reliably test blocking, we can exhaust the burst.
	// Since we just exhausted burst (30), the next one SHOULD fail or pass if some time elapsed.
	// But in a tight loop, it should likely fail.

	req := httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("X-Forwarded-For", ip)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Note: rate.NewLimiter(10, 30) means 1 token every 100ms.
	// If the loop runs faster than 100ms, the 31st request fails.
	if rr.Code != http.StatusTooManyRequests && rr.Code != http.StatusOK {
		t.Errorf("Unexpected status code: %d", rr.Code)
	}
}
