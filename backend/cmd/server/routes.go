package main

import (
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

func (s *Server) setupRoutes() {
	// Health check
	http.HandleFunc("/health", corsMiddleware(s.handleHealth))

	// Auth
	http.HandleFunc("/api/login", corsMiddleware(s.handleLogin))

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
}
