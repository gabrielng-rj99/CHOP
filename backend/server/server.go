package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"Open-Generic-Hub/backend/config"
	"Open-Generic-Hub/backend/store"
)

type Server struct {
	userStore      *store.UserStore
	contractStore  *store.ContractStore
	clientStore    *store.ClientStore
	dependentStore *store.DependentStore
	categoryStore  *store.CategoryStore
	lineStore      *store.LineStore
	auditStore     *store.AuditStore
	config         *config.Config
}

// NewServer creates a new Server instance with all stores
func NewServer(db *sql.DB) *Server {
	cfg := config.GetConfig()

	// Only create stores if database is available
	// This allows the server to start for initial setup/deploy panel
	var userStore *store.UserStore
	var contractStore *store.ContractStore
	var clientStore *store.ClientStore
	var dependentStore *store.DependentStore
	var categoryStore *store.CategoryStore
	var lineStore *store.LineStore
	var auditStore *store.AuditStore

	if db != nil {
		userStore = store.NewUserStore(db)
		contractStore = store.NewContractStore(db)
		clientStore = store.NewClientStore(db)
		dependentStore = store.NewDependentStore(db)
		categoryStore = store.NewCategoryStore(db)
		lineStore = store.NewLineStore(db)
		auditStore = store.NewAuditStore(db)
	}

	return &Server{
		userStore:      userStore,
		contractStore:  contractStore,
		clientStore:    clientStore,
		dependentStore: dependentStore,
		categoryStore:  categoryStore,
		lineStore:      lineStore,
		auditStore:     auditStore,
		config:         cfg,
	}
}

// InitializeStores initializes all stores with the provided database connection
func (s *Server) InitializeStores(db *sql.DB) {
	if db != nil {
		s.userStore = store.NewUserStore(db)
		s.contractStore = store.NewContractStore(db)
		s.clientStore = store.NewClientStore(db)
		s.dependentStore = store.NewDependentStore(db)
		s.categoryStore = store.NewCategoryStore(db)
		s.lineStore = store.NewLineStore(db)
		s.auditStore = store.NewAuditStore(db)
	}
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// isOriginAllowed checks if the origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("CORS MIDDLEWARE EXECUTADO: %s %s", r.Method, r.URL.Path)
		// Panic recovery
		defer func() {
			if err := recover(); err != nil {
				fmt.Fprintf(os.Stderr, "PANIC in handler %s %s: %v\n", r.Method, r.URL.Path, err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		origin := r.Header.Get("Origin")
		log.Printf("CORS: Origin recebido: '%s' | Method: %s | Path: %s", origin, r.Method, r.URL.Path)

		// Check if origin is allowed
		if origin != "" && isOriginAllowed(origin, s.config.Server.CORSOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)

			if s.config.Server.CORSAllowCreds {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			w.Header().Set("Access-Control-Allow-Methods", strings.Join(s.config.Server.CORSMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(s.config.Server.CORSHeaders, ", "))

			if len(s.config.Server.CORSExposeHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(s.config.Server.CORSExposeHeaders, ", "))
			}

			if s.config.Server.CORSMaxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", s.config.Server.CORSMaxAge))
			}
		} else if origin != "" {
			// Origin not allowed - log for security audit
			log.Printf("CORS: Origin not allowed: %s (allowed: %v)", origin, s.config.Server.CORSOrigins)
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, ErrorResponse{Error: message})
}

func getIDFromPath(r *http.Request, prefix string) string {
	path := strings.TrimPrefix(r.URL.Path, prefix)
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return ""
}
