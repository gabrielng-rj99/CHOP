package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

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
}

// NewServer creates a new Server instance with all stores
func NewServer(db *sql.DB) *Server {
	return &Server{
		userStore:      store.NewUserStore(db),
		contractStore:  store.NewContractStore(db),
		clientStore:    store.NewClientStore(db),
		dependentStore: store.NewDependentStore(db),
		categoryStore:  store.NewCategoryStore(db),
		lineStore:      store.NewLineStore(db),
		auditStore:     store.NewAuditStore(db),
	}
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
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
