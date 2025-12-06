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
	"context"
	"log"
	"net/http"
	"strings"
	"time"
)

// ============= HEALTH HANDLER =============

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	db := GetGlobalDB()
	if db == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":    "unhealthy",
			"message":   "Database not connected",
			"timestamp": time.Now().Format(time.RFC3339),
		})
		return
	}

	// Test database connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":    "unhealthy",
			"message":   "Database connection failed",
			"timestamp": time.Now().Format(time.RFC3339),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// standardMiddleware applies all standard security middlewares
func (s *Server) standardMiddleware(next http.HandlerFunc) http.HandlerFunc {
	// Logging should be the outermost to capture everything including CORS/RateLimit effects if possible,
	// but usually CORS is outermost for browser preflight.
	// Order: Logging -> CORS -> SecurityHeaders -> RateLimit -> Handler
	return s.loggingMiddleware(s.corsMiddleware(s.securityHeadersMiddleware(s.rateLimitMiddleware(next))))
}

// ============= ROUTER SETUP =============

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractTokenFromHeader(r)
		if tokenString == "" {
			log.Printf("Requisição sem token para %s %s", r.Method, r.URL.Path)
			respondError(w, http.StatusUnauthorized, "Token não fornecido")
			return
		}

		claims, err := ValidateJWT(tokenString, s.userStore)
		if err != nil {
			log.Printf("Token inválido ou expirado para %s %s: %v", r.Method, r.URL.Path, err)
			respondError(w, http.StatusUnauthorized, "Token inválido ou expirado. Faça login novamente.")
			return
		}

		// Inject user info for logging
		setRequestUser(r, claims)

		log.Printf("Requisição autenticada: username=%s, role=%s, method=%s, path=%s", claims.Username, claims.Role, r.Method, r.URL.Path)
		next(w, r)
	}
}

// adminOnlyMiddleware restricts access to admin and root users only
// Must be used after authMiddleware
func (s *Server) adminOnlyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractTokenFromHeader(r)
		claims, err := ValidateJWT(tokenString, s.userStore)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "Token inválido")
			return
		}

		if claims.Role != "admin" && claims.Role != "root" {
			log.Printf("🚫 Acesso negado: usuário %s (role: %s) tentou acessar recurso administrativo %s %s",
				claims.Username, claims.Role, r.Method, r.URL.Path)
			respondError(w, http.StatusForbidden, "Acesso negado. Apenas administradores podem acessar este recurso.")
			return
		}

		next(w, r)
	}
}

// rootOnlyMiddleware restricts access to root users only
// Must be used after authMiddleware
func (s *Server) rootOnlyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractTokenFromHeader(r)
		claims, err := ValidateJWT(tokenString, s.userStore)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "Token inválido")
			return
		}

		if claims.Role != "root" {
			log.Printf("🚫 Acesso negado: usuário %s (role: %s) tentou acessar recurso exclusivo de root %s %s",
				claims.Username, claims.Role, r.Method, r.URL.Path)
			respondError(w, http.StatusForbidden, "Acesso negado. Apenas usuários root podem acessar este recurso.")
			return
		}

		next(w, r)
	}
}

// Handler returns an http.Handler with all routes configured (for testing)
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	return mux
}

// SetupRoutes configures routes on the default ServeMux (for production)
func (s *Server) SetupRoutes() {
	s.registerRoutes(http.DefaultServeMux)
}

// registerRoutes registers all routes on the provided ServeMux
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Health check
	mux.HandleFunc("/health", s.standardMiddleware(s.handleHealth))

	// Auth
	mux.HandleFunc("/api/login", s.standardMiddleware(s.handleLogin))
	mux.HandleFunc("/api/refresh-token", s.standardMiddleware(s.handleRefreshToken))

	// Users - admin/root only for management operations
	mux.HandleFunc("/api/users/", s.standardMiddleware(s.authMiddleware(s.adminOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/block") {
			s.handleUserBlock(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unlock") {
			s.handleUserUnlock(w, r)
		} else {
			s.handleUserByUsername(w, r)
		}
	}))))
	mux.HandleFunc("/api/users", s.standardMiddleware(s.authMiddleware(s.adminOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Se o path é exatamente /api/users (sem ID), chama handleUsers
		if r.URL.Path == "/api/users" {
			s.handleUsers(w, r)
		} else {
			// Caso contrário, trata como /api/users/{username}
			if strings.HasSuffix(r.URL.Path, "/block") {
				s.handleUserBlock(w, r)
			} else if strings.HasSuffix(r.URL.Path, "/unlock") {
				s.handleUserUnlock(w, r)
			} else {
				s.handleUserByUsername(w, r)
			}
		}
	}))))

	// Clients
	mux.HandleFunc("/api/entities/", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/archive") {
			s.handleEntityArchive(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
			s.handleEntityUnarchive(w, r)
		} else if strings.Contains(r.URL.Path, "/sub_entities") {
			s.handleEntitySubEntities(w, r)
		} else {
			s.handleEntityByID(w, r)
		}
	})))
	mux.HandleFunc("/api/entities", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/entities" {
			s.handleEntities(w, r)
		} else {
			if strings.HasSuffix(r.URL.Path, "/archive") {
				s.handleEntityArchive(w, r)
			} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
				s.handleEntityUnarchive(w, r)
			} else if strings.Contains(r.URL.Path, "/sub_entities") {
				s.handleEntitySubEntities(w, r)
			} else {
				s.handleEntityByID(w, r)
			}
		}
	})))

	// Dependents
	mux.HandleFunc("/api/sub-entities/", s.standardMiddleware(s.authMiddleware(s.handleSubEntityByID)))

	// Contracts
	mux.HandleFunc("/api/agreements/", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/archive") {
			s.handleAgreementArchive(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
			s.handleAgreementUnarchive(w, r)
		} else {
			s.handleAgreementByID(w, r)
		}
	})))
	mux.HandleFunc("/api/agreements", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agreements" {
			s.handleAgreements(w, r)
		} else {
			if strings.HasSuffix(r.URL.Path, "/archive") {
				s.handleAgreementArchive(w, r)
			} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
				s.handleAgreementUnarchive(w, r)
			} else {
				s.handleAgreementByID(w, r)
			}
		}
	})))

	// Categories
	mux.HandleFunc("/api/categories/", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/subcategories") {
			s.handleCategorySubcategories(w, r)
		} else {
			s.handleCategoryByID(w, r)
		}
	})))
	mux.HandleFunc("/api/categories", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/categories" {
			s.handleCategories(w, r)
		} else {
			if strings.Contains(r.URL.Path, "/subcategories") {
				s.handleCategorySubcategories(w, r)
			} else {
				s.handleCategoryByID(w, r)
			}
		}
	})))

	// Lines
	mux.HandleFunc("/api/subcategories/", s.standardMiddleware(s.authMiddleware(s.handleSubcategoryByID)))
	mux.HandleFunc("/api/subcategories", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/subcategories" {
			s.handleSubcategories(w, r)
		} else {
			s.handleSubcategoryByID(w, r)
		}
	})))

	// Audit Logs (only accessible to root)
	mux.HandleFunc("/api/audit-logs/", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Apenas root pode acessar
		claims, err := ValidateJWT(extractTokenFromHeader(r), s.userStore)
		if err != nil || claims.Role != "root" {
			respondError(w, http.StatusForbidden, "Apenas root pode acessar logs de auditoria")
			return
		}

		if strings.HasSuffix(r.URL.Path, "/export") {
			s.handleAuditLogsExport(w, r)
		} else if strings.Contains(r.URL.Path, "/entity/") {
			s.handleAuditLogsByEntity(w, r)
		} else {
			s.handleAuditLogDetail(w, r)
		}
	})))
	mux.HandleFunc("/api/audit-logs", s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Apenas root pode acessar
		claims, err := ValidateJWT(extractTokenFromHeader(r), s.userStore)
		if err != nil || claims.Role != "root" {
			respondError(w, http.StatusForbidden, "Apenas root pode acessar logs de auditoria")
			return
		}

		if r.URL.Path == "/api/audit-logs" {
			s.handleAuditLogs(w, r)
		} else {
			if strings.HasSuffix(r.URL.Path, "/export") {
				s.handleAuditLogsExport(w, r)
			} else if strings.Contains(r.URL.Path, "/entity/") {
				s.handleAuditLogsByEntity(w, r)
			} else {
				s.handleAuditLogDetail(w, r)
			}
		}
	})))

	// Deploy Configuration (accessible without auth in development, with token in production)
	mux.HandleFunc("/api/deploy/config", s.standardMiddleware(s.HandleDeployConfig))
	mux.HandleFunc("/api/deploy/config/defaults", s.standardMiddleware(s.HandleDeployConfigDefaults))
	mux.HandleFunc("/api/deploy/status", s.standardMiddleware(s.HandleDeployStatus))
	mux.HandleFunc("/api/deploy/validate", s.corsMiddleware(s.HandleDeployValidate))

	// Initialize Admin (accessible only when database is completely empty)
	mux.HandleFunc("/api/initialize/admin", s.corsMiddleware(s.HandleInitializeAdmin))
	mux.HandleFunc("/api/initialize/status", s.corsMiddleware(s.HandleInitializeStatus))
}
