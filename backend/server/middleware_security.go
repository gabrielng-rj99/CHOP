package server

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPRateLimiter holds rate limiters for each IP
type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  sync.RWMutex
	r   rate.Limit
	b   int
}

// NewIPRateLimiter creates a new rate limiter
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}

	// Clean up old entries periodically to prevent memory leaks
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			i.cleanup()
		}
	}()

	return i
}

// AddIP adds an IP to the map
func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)
	i.ips[ip] = limiter
	return limiter
}

// GetLimiter returns the rate limiter for the provided IP address
// If it doesn't exist, it creates a new one
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.RLock()
	limiter, exists := i.ips[ip]
	i.mu.RUnlock()

	if !exists {
		return i.AddIP(ip)
	}

	return limiter
}

func (i *IPRateLimiter) cleanup() {
	i.mu.Lock()
	// In a real implementation, we would track last access time and remove old ones
	// For now, we just reset the map if it gets too big to avoid memory exhaustion
	if len(i.ips) > 10000 {
		i.ips = make(map[string]*rate.Limiter)
	}
	i.mu.Unlock()
}

// Global limiter instance (5 requests per second, burst of 10)
var limiter = NewIPRateLimiter(5, 10)

// RateLimitMiddleware enforces rate limiting per IP
func (s *Server) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ipPtr := getIPAddress(r)
		ip := "unknown"
		if ipPtr != nil {
			ip = *ipPtr
		}

		limiter := limiter.GetLimiter(ip)
		if !limiter.Allow() {
			respondError(w, http.StatusTooManyRequests, "Rate limit exceeded")
			return
		}
		next(w, r)
	}
}

// SecurityHeadersMiddleware adds security headers to responses
func (s *Server) securityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// XSS Protection (legacy but useful)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Content Security Policy (Basic)
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		// HSTS (Strict Transport Security) - 1 year
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next(w, r)
	}
}
