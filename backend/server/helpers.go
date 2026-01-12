/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
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
	"html"
	"net/http"
	"regexp"
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

	// Fallback to RemoteAddr - handle both IPv4 and IPv6
	remoteAddr := r.RemoteAddr

	// Check if it's IPv6 format [ip]:port
	if strings.HasPrefix(remoteAddr, "[") {
		// IPv6 format: [::1]:port or [2001:db8::1]:port
		if idx := strings.LastIndex(remoteAddr, "]:"); idx != -1 {
			ip := remoteAddr[1:idx] // Remove [ and everything after ]:
			return &ip
		}
		// No port, just [ip]
		ip := strings.Trim(remoteAddr, "[]")
		return &ip
	}

	// IPv4 format: 192.168.1.1:port
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		ip := remoteAddr[:idx]
		return &ip
	}

	// No port in address
	return &remoteAddr
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

// sanitizeHTML removes HTML tags and escapes special characters to prevent XSS attacks
func sanitizeHTML(input string) string {
	if input == "" {
		return input
	}

	// Remove all HTML tags
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	sanitized := htmlTagRegex.ReplaceAllString(input, "")

	// Remove javascript: protocol
	jsProtocolRegex := regexp.MustCompile(`(?i)javascript:`)
	sanitized = jsProtocolRegex.ReplaceAllString(sanitized, "")

	// Remove event handlers (onclick, onerror, onload, etc.)
	eventHandlerRegex := regexp.MustCompile(`(?i)\bon\w+\s*=`)
	sanitized = eventHandlerRegex.ReplaceAllString(sanitized, "")

	// Escape HTML special characters
	sanitized = html.EscapeString(sanitized)

	return sanitized
}

// sanitizeDisplayName sanitizes a display name to prevent XSS
func sanitizeDisplayName(displayName string) string {
	return sanitizeHTML(displayName)
}
