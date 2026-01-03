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
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

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
		"affiliates",
		"categories",
		"subcategories",
		"contracts",
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
// GET /api/initialize/status - Read-only endpoint to check system initialization status
// 🔒 SECURITY: Only GET method allowed. POST/PUT/DELETE/PATCH are strictly forbidden.
func (s *Server) HandleInitializeStatus(w http.ResponseWriter, r *http.Request) {
	// 🔒 STRICT METHOD VALIDATION: Only GET is allowed
	if r.Method != http.MethodGet {
		ip := getIPAddress(r)
		ipStr := ""
		if ip != nil {
			ipStr = *ip
		}
		log.Printf("🚨 SECURITY: Blocked non-GET request to /api/initialize/status: method=%s from IP=%s", r.Method, ipStr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 🔒 SECURITY: Prevent query parameter manipulation attempts
	// This endpoint should not accept any query parameters
	if len(r.URL.Query()) > 0 {
		ip := getIPAddress(r)
		ipStr := ""
		if ip != nil {
			ipStr = *ip
		}
		log.Printf("⚠️  WARNING: /api/initialize/status called with query parameters from IP=%s: %v", ipStr, r.URL.Query())
	}

	response := InitializeStatusResponse{
		HasDatabase:    false,
		DatabaseEmpty:  false,
		IsInitialized:  false,
		RequiresSetup:  false,
		DatabaseStatus: "unknown",
		Message:        "Initialization not complete",
	}

	// 🔒 SECURITY: Attempt database connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := database.ConnectDB()
	if err != nil {
		log.Printf("⚠️  Database connection error during status check: %v", err)
		response.DatabaseStatus = "error"
		response.RequiresSetup = true
		response.Message = "Database not configured or not accessible"

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}
	defer db.Close()

	// 🔒 SECURITY: Verify database connection is actually working
	if err := db.PingContext(ctx); err != nil {
		log.Printf("⚠️  Database ping failed during status check: %v", err)
		response.DatabaseStatus = "error"
		response.RequiresSetup = true
		response.Message = "Database connection test failed"

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	response.HasDatabase = true
	response.DatabaseStatus = "connected"

	// 🔒 SECURITY: Verifica se o banco está completamente vazio
	// This check is critical - it prevents /initialize/admin from being called when system is already initialized
	isEmpty, tablesWithData, err := checkDatabaseEmpty(db)
	if err != nil {
		log.Printf("❌ Error checking database status: %v", err)
		response.DatabaseStatus = "error"
		response.Message = "Error checking database status"
		response.RequiresSetup = true
	} else {
		response.DatabaseEmpty = isEmpty
		response.TablesWithData = tablesWithData

		if isEmpty {
			// 🔒 SECURITY: Banco vazio - precisa de setup inicial
			// Only return requires_setup=true if database is COMPLETELY empty
			response.DatabaseStatus = "empty"
			response.RequiresSetup = true
			response.IsInitialized = false
			response.Message = "Database is empty. Admin creation required."
			log.Printf("ℹ️  Database is empty - system initialization required")
		} else {
			// 🔒 SECURITY: Banco tem dados - sistema já foi inicializado
			// IMPORTANT: Once any data exists, initialization is locked forever
			response.DatabaseStatus = "has_data"
			response.RequiresSetup = false
			response.IsInitialized = true
			response.Message = "System fully initialized"
			log.Printf("✅ System is initialized with %d tables containing data", len(tablesWithData))
		}
	}

	// 🔒 SECURITY: Set response headers to prevent caching of initialization status
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
