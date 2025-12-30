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
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// requestLogDataKey is the key context for the RequestLogData pointer
	requestLogDataKey contextKey = "requestLogData"
)

// RequestLogData holds data that subsequent middlewares/handlers can populate
// so the logging middleware can record it at the end of the request.
type RequestLogData struct {
	UserID   string
	Username string
	Role     string
}

// responseWriterWrapper wraps http.ResponseWriter to capture the status code
type responseWriterWrapper struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriterWrapper {
	return &responseWriterWrapper{ResponseWriter: w}
}

func (rw *responseWriterWrapper) Status() int {
	return rw.status
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true
}

// loggingMiddleware captures request details and logs them after completion
func (s *Server) loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create shared data container and inject into context
		logData := &RequestLogData{}
		ctx := context.WithValue(r.Context(), requestLogDataKey, logData)
		r = r.WithContext(ctx)

		wrapped := wrapResponseWriter(w)
		// Default to 200 OK if WriteHeader is never called
		wrapped.status = http.StatusOK

		// Process request
		next(wrapped, r)

		duration := time.Since(start)

		// Determine user string
		userStr := "Anonymous"
		if logData.Username != "" {
			userStr = fmt.Sprintf("%s (ID: %s, Role: %s)", logData.Username, logData.UserID, logData.Role)
		}

		ip := *getIPAddress(r)

		// [TIME] [METHOD] [PATH] | Status: [CODE] | Dur: [TIME] | IP: [IP] | User: [USER]
		log.Printf(
			"%s %s | Status: %d | Dur: %v | IP: %s | User: %s",
			r.Method,
			r.URL.Path,
			wrapped.Status(),
			duration,
			ip,
			userStr,
		)
	}
}

// setRequestUser allows auth middleware to set the user for logging
func setRequestUser(r *http.Request, claims *JWTClaims) {
	if val := r.Context().Value(requestLogDataKey); val != nil {
		if logData, ok := val.(*RequestLogData); ok {
			logData.UserID = claims.UserID
			logData.Username = claims.Username
			logData.Role = claims.Role
		}
	}
}
