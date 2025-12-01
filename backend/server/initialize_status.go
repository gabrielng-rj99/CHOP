package server

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"Open-Generic-Hub/backend/database"
)

// InitializeStatusResponse representa o status de inicialização
type InitializeStatusResponse struct {
	IsInitialized  bool     `json:"is_initialized"`
	HasDatabase    bool     `json:"has_database"`
	DatabaseEmpty  bool     `json:"database_empty"`
	RequiresSetup  bool     `json:"requires_setup"`
	Message        string   `json:"message"`
	DatabaseStatus string   `json:"database_status,omitempty"` // "empty", "has_data", "connected", "error"
	TablesWithData []string `json:"tables_with_data,omitempty"`
}

// checkDatabaseEmpty verifica se TODAS as tabelas principais estão vazias
func checkDatabaseEmpty(db *sql.DB) (bool, []string, error) {
	tables := []string{
		"users",
		"clients",
		"dependents",
		"categories",
		"lines",
		"contracts",
		"audit_logs",
	}

	var tablesWithData []string

	for _, table := range tables {
		var count int
		query := "SELECT COUNT(*) FROM " + table
		err := db.QueryRow(query).Scan(&count)
		if err != nil {
			return false, nil, err
		}

		if count > 0 {
			tablesWithData = append(tablesWithData, table)
		}
	}

	isEmpty := len(tablesWithData) == 0
	return isEmpty, tablesWithData, nil
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
		DatabaseEmpty:  false,
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

	// Verifica se o banco está completamente vazio
	isEmpty, tablesWithData, err := checkDatabaseEmpty(db)
	if err != nil {
		response.DatabaseStatus = "error"
		response.Message = "Error checking database status"
		response.RequiresSetup = true
	} else {
		response.DatabaseEmpty = isEmpty
		response.TablesWithData = tablesWithData

		if isEmpty {
			// Banco vazio - precisa de setup inicial
			response.DatabaseStatus = "empty"
			response.RequiresSetup = true
			response.IsInitialized = false
			response.Message = "Database is empty. Admin creation required."
		} else {
			// Banco tem dados - sistema inicializado
			response.DatabaseStatus = "has_data"
			response.RequiresSetup = false
			response.IsInitialized = true
			response.Message = "System fully initialized"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
