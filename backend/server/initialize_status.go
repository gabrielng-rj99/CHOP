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
	"database/sql"
	"encoding/json"
	"log"
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
		"entities",
		"sub_entities",
		"categories",
		"subcategories",
		"agreements",
		"audit_logs",
	}

	var tablesWithData []string

	for _, table := range tables {
		var count int
		query := "SELECT COUNT(*) FROM " + table
		err := db.QueryRow(query).Scan(&count)
		if err != nil {
			log.Printf("Error checking table '%s': %v", table, err)
			return false, nil, err
		}

		log.Printf("Table '%s' has %d rows", table, count)
		if count > 0 {
			tablesWithData = append(tablesWithData, table)
		}
	}

	isEmpty := len(tablesWithData) == 0
	log.Printf("Database empty check: isEmpty=%v, tablesWithData=%v", isEmpty, tablesWithData)
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
