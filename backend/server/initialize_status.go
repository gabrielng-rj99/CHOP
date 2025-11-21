package server

import (
	"encoding/json"
	"net/http"

	"Open-Generic-Hub/backend/database"
	"Open-Generic-Hub/backend/store"
)

// InitializeStatusResponse representa o status de inicialização
type InitializeStatusResponse struct {
	IsInitialized  bool   `json:"is_initialized"`
	HasDatabase    bool   `json:"has_database"`
	HasUsers       bool   `json:"has_users"`
	RequiresSetup  bool   `json:"requires_setup"`
	Message        string `json:"message"`
	DatabaseStatus string `json:"database_status,omitempty"` // "empty", "connected", "error"
	UsersCount     int    `json:"users_count,omitempty"`
	RootUserExists bool   `json:"root_user_exists,omitempty"`
}

// HandleInitializeStatus verifica status de inicialização
// GET /api/initialize/status
func (s *Server) HandleInitializeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := InitializeStatusResponse{
		HasDatabase:    false,
		HasUsers:       false,
		IsInitialized:  false,
		RequiresSetup:  false,
		DatabaseStatus: "unknown",
		Message:        "Initialization not complete",
	}

	// Tenta conectar ao banco
	db, err := database.ConnectDB()
	if err != nil {
		response.DatabaseStatus = "error"
		response.RequiresSetup = true
		response.Message = "Database not configured or not accessible"

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}
	defer db.Close()

	response.HasDatabase = true
	response.DatabaseStatus = "connected"

	// Verifica se existem usuários
	userStore := store.NewUserStore(db)

	// Contar usuários
	users, err := userStore.ListUsers()
	if err != nil {
		response.Message = "Error checking users"
		response.RequiresSetup = true
	} else {
		response.UsersCount = len(users)

		// Verificar se existe usuário root
		for _, user := range users {
			if user.Role != nil && *user.Role == "root" {
				response.RootUserExists = true
				break
			}
		}

		if response.UsersCount == 0 {
			response.HasUsers = false
			response.RequiresSetup = true
			response.Message = "Database connected but no users. Setup required."
		} else if !response.RootUserExists {
			response.RequiresSetup = true
			response.Message = "Users exist but no root user. Admin creation required."
		} else {
			response.IsInitialized = true
			response.HasUsers = true
			response.RequiresSetup = false
			response.Message = "System fully initialized"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
