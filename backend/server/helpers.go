package server

import (
	"net/http"
	"strings"
)

// getIPAddress extrai o endereço IP do cliente da requisição HTTP
func getIPAddress(r *http.Request) *string {
	// Try X-Forwarded-For first (for proxies/load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		ip := strings.TrimSpace(ips[0])
		return &ip
	}

	// Try X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return &xri
	}

	// Fallback to RemoteAddr
	ip := strings.Split(r.RemoteAddr, ":")[0]
	return &ip
}

// getUserAgent extrai o User-Agent da requisição HTTP
func getUserAgent(r *http.Request) *string {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		return nil
	}
	return &ua
}

// getRequestMethod retorna o método HTTP da requisição
func getRequestMethod(r *http.Request) *string {
	method := r.Method
	return &method
}

// getRequestPath retorna o path da URL da requisição
func getRequestPath(r *http.Request) *string {
	path := r.URL.Path
	return &path
}

// stringToPtr converte uma string para *string
func stringToPtr(s string) *string {
	return &s
}

// bytesToStringPtr converte []byte para *string
func bytesToStringPtr(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	return &s
}
