package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// ============= HEALTH HANDLER =============

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) setupRoutes() {
	// Health check
	http.HandleFunc("/health", corsMiddleware(s.handleHealth))

	// Auth
	http.HandleFunc("/api/login", corsMiddleware(s.handleLogin))
	http.HandleFunc("/api/refresh-token", corsMiddleware(s.handleRefreshToken))

	// Users
	http.HandleFunc("/api/users/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/block") {
			s.handleUserBlock(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unlock") {
			s.handleUserUnlock(w, r)
		} else {
			s.handleUserByUsername(w, r)
		}
	})))
	http.HandleFunc("/api/users", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	})))

	// Clients
	http.HandleFunc("/api/clients/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/api/clients", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/api/dependents/", corsMiddleware(s.authMiddleware(s.handleDependentByID)))

	// Contracts
	http.HandleFunc("/api/contracts/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/archive") {
			s.handleContractArchive(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
			s.handleContractUnarchive(w, r)
		} else {
			s.handleContractByID(w, r)
		}
	})))
	http.HandleFunc("/api/contracts", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/api/categories/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/lines") {
			s.handleCategoryLines(w, r)
		} else {
			s.handleCategoryByID(w, r)
		}
	})))
	http.HandleFunc("/api/categories", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	http.HandleFunc("/api/lines/", corsMiddleware(s.authMiddleware(s.handleLineByID)))
	http.HandleFunc("/api/lines", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/lines" {
			s.handleLines(w, r)
		} else {
			s.handleLineByID(w, r)
		}
	})))

	// Audit Logs (only accessible to full_admin)
	http.HandleFunc("/api/audit-logs/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Apenas full_admin pode acessar
		claims, err := ValidateJWT(extractTokenFromHeader(r), s.userStore)
		if err != nil || claims.Role != "full_admin" {
			respondError(w, http.StatusForbidden, "Apenas full_admin pode acessar logs de auditoria")
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
	http.HandleFunc("/api/audit-logs", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Apenas full_admin pode acessar
		claims, err := ValidateJWT(extractTokenFromHeader(r), s.userStore)
		if err != nil || claims.Role != "full_admin" {
			respondError(w, http.StatusForbidden, "Apenas full_admin pode acessar logs de auditoria")
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
}
