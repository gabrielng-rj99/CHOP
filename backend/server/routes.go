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
	mux.HandleFunc("/health", s.corsMiddleware(s.handleHealth))

	// Auth
	mux.HandleFunc("/api/login", s.corsMiddleware(s.handleLogin))
	mux.HandleFunc("/api/refresh-token", s.corsMiddleware(s.handleRefreshToken))

	// Users - admin/root only for management operations
	mux.HandleFunc("/api/users/", s.corsMiddleware(s.authMiddleware(s.adminOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/block") {
			s.handleUserBlock(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unlock") {
			s.handleUserUnlock(w, r)
		} else {
			s.handleUserByUsername(w, r)
		}
	}))))
	mux.HandleFunc("/api/users", s.corsMiddleware(s.authMiddleware(s.adminOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/api/clients/", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/archive") {
			s.handleClientArchive(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
			s.handleClientUnarchive(w, r)
		} else if strings.Contains(r.URL.Path, "/dependents") {
			s.handleClientDependents(w, r)
		} else {
			s.handleClientByID(w, r)
		}
	})))
	mux.HandleFunc("/api/clients", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/clients" {
			s.handleClients(w, r)
		} else {
			if strings.HasSuffix(r.URL.Path, "/archive") {
				s.handleClientArchive(w, r)
			} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
				s.handleClientUnarchive(w, r)
			} else if strings.Contains(r.URL.Path, "/dependents") {
				s.handleClientDependents(w, r)
			} else {
				s.handleClientByID(w, r)
			}
		}
	})))

	// Dependents
	mux.HandleFunc("/api/dependents/", s.corsMiddleware(s.authMiddleware(s.handleDependentByID)))

	// Contracts
	mux.HandleFunc("/api/contracts/", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/archive") {
			s.handleContractArchive(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
			s.handleContractUnarchive(w, r)
		} else {
			s.handleContractByID(w, r)
		}
	})))
	mux.HandleFunc("/api/contracts", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/contracts" {
			s.handleContracts(w, r)
		} else {
			if strings.HasSuffix(r.URL.Path, "/archive") {
				s.handleContractArchive(w, r)
			} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
				s.handleContractUnarchive(w, r)
			} else {
				s.handleContractByID(w, r)
			}
		}
	})))

	// Categories
	mux.HandleFunc("/api/categories/", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/lines") {
			s.handleCategoryLines(w, r)
		} else {
			s.handleCategoryByID(w, r)
		}
	})))
	mux.HandleFunc("/api/categories", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/categories" {
			s.handleCategories(w, r)
		} else {
			if strings.Contains(r.URL.Path, "/lines") {
				s.handleCategoryLines(w, r)
			} else {
				s.handleCategoryByID(w, r)
			}
		}
	})))

	// Lines
	mux.HandleFunc("/api/lines/", s.corsMiddleware(s.authMiddleware(s.handleLineByID)))
	mux.HandleFunc("/api/lines", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/lines" {
			s.handleLines(w, r)
		} else {
			s.handleLineByID(w, r)
		}
	})))

	// Audit Logs (only accessible to root)
	mux.HandleFunc("/api/audit-logs/", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/api/audit-logs", s.corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/api/deploy/config", s.corsMiddleware(s.HandleDeployConfig))
	mux.HandleFunc("/api/deploy/config/defaults", s.corsMiddleware(s.HandleDeployConfigDefaults))
	mux.HandleFunc("/api/deploy/status", s.corsMiddleware(s.HandleDeployStatus))
	mux.HandleFunc("/api/deploy/validate", s.corsMiddleware(s.HandleDeployValidate))

	// Initialize Admin (accessible only when database is completely empty)
	mux.HandleFunc("/api/initialize/admin", s.corsMiddleware(s.HandleInitializeAdmin))
	mux.HandleFunc("/api/initialize/status", s.corsMiddleware(s.HandleInitializeStatus))
}
