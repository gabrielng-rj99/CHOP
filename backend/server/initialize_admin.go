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
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"Open-Generic-Hub/backend/database"
	"Open-Generic-Hub/backend/store"
)

// Mutex to prevent race conditions during initialization
var initMutex sync.Mutex

// InitializeAdminRequest represents the request to create root admin
type InitializeAdminRequest struct {
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Password    string `json:"password,omitempty"`
}

// InitializeAdminResponse represents the response from admin initialization
type InitializeAdminResponse struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message"`
	Errors        []string `json:"errors,omitempty"`
	AdminID       string   `json:"admin_id,omitempty"`
	AdminUsername string   `json:"admin_username,omitempty"`
	AdminPassword string   `json:"admin_password,omitempty"`
}

// isDatabaseEmpty checks if ALL main tables in the database are empty
// Returns true only if database has NO data at all
func isDatabaseEmpty(db *sql.DB) (bool, error) {
	tables := []string{
		"users",
		"clients",
		"affiliates",
		"categories",
		"subcategories",
		"contracts",
	}

	for _, table := range tables {
		var count int
		query := "SELECT COUNT(*) FROM " + table
		err := db.QueryRow(query).Scan(&count)
		if err != nil {
			return false, err
		}

		if count > 0 {
			log.Printf("⚠️  SECURITY: Table '%s' has %d record(s) - database is NOT empty", table, count)
			return false, nil
		}
	}

	return true, nil
}

// HandleInitializeAdmin handles the admin initialization endpoint
// POST /api/initialize/admin - Creates the root admin user
// 🔒 CRITICAL SECURITY: This endpoint is ONLY accessible when database is COMPLETELY EMPTY
func (s *Server) HandleInitializeAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 🔒 RACE CONDITION PROTECTION: Only one initialization can happen at a time
	initMutex.Lock()
	defer initMutex.Unlock()

	// 🔒 STEP 1: Connect to database to verify it's empty
	db, err := database.ConnectDB()
	if err != nil {
		log.Printf("❌ InitializeAdmin: Failed to connect to database: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InitializeAdminResponse{
			Success: false,
			Message: "Failed to connect to database",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Only close DB if we return early (error or blocked)
	// If successful, we pass it to the stores, so we must keep it open
	shouldCloseDB := true
	defer func() {
		if shouldCloseDB {
			db.Close()
		}
	}()

	// 🔒 STEP 2: CRITICAL SECURITY CHECK - Verify database is COMPLETELY EMPTY
	isEmpty, err := isDatabaseEmpty(db)
	if err != nil {
		log.Printf("❌ InitializeAdmin: Failed to verify database status: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InitializeAdminResponse{
			Success: false,
			Message: "Failed to verify database status",
			Errors:  []string{err.Error()},
		})
		return
	}

	// 🚨 SECURITY BLOCK: If database has ANY data, reject the request
	if !isEmpty {
		log.Printf("🚨 SECURITY ALERT: Blocked admin creation attempt - Database contains data")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(InitializeAdminResponse{
			Success: false,
			Message: "System already initialized. Admin creation is ONLY allowed when database is completely empty.",
			Errors:  []string{"Database contains existing data. This endpoint is blocked for security reasons."},
		})
		return
	}

	log.Printf("✅ Security check passed: Database is empty, proceeding with admin creation")

	// Parse request body
	var req InitializeAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InitializeAdminResponse{
			Success: false,
			Message: "Invalid request payload",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Validate input using the same strong validation as regular user creation
	var errors []string

	if req.DisplayName == "" {
		errors = append(errors, "Display name is required")
	}

	// 🔒 SECURITY: Use the same strong password validation as regular users
	if req.Password == "" {
		errors = append(errors, "Password is required")
	} else {
		// Use store validation for consistent password policy
		if err := store.ValidateStrongPassword(req.Password); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// Validate username if provided
	if req.Username != "" {
		if err := store.ValidateUsername(req.Username); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InitializeAdminResponse{
			Success: false,
			Message: "Validation failed",
			Errors:  errors,
		})
		return
	}

	// Default username if not provided
	username := req.Username
	if username == "" {
		username = "root"
	}

	// Create the root admin user
	userStore := store.NewUserStore(db)
	adminID, err := userStore.CreateUser(username, req.DisplayName, req.Password, "root")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InitializeAdminResponse{
			Success: false,
			Message: "Failed to create admin user",
			Errors:  []string{err.Error()},
		})
		return
	}

	log.Printf("✅ Root admin user created via API (ID: %s, username: %s)", adminID, username)

	// Reinitialize server stores with the database connection
	// This makes the server fully operational after admin creation
	s.userStore = store.NewUserStore(db)
	s.contractStore = store.NewContractStore(db)
	s.clientStore = store.NewClientStore(db)
	s.affiliateStore = store.NewAffiliateStore(db)
	s.categoryStore = store.NewCategoryStore(db)
	s.subcategoryStore = store.NewSubcategoryStore(db)
	s.auditStore = store.NewAuditStore(db)

	log.Printf("✅ Server stores reinitialized with database connection")

	// 🔒 SECURITY: Do NOT return the password in the response
	// The client already knows the password they sent
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(InitializeAdminResponse{
		Success:       true,
		Message:       "Root admin user created successfully",
		AdminID:       adminID,
		AdminUsername: username,
		// AdminPassword intentionally omitted for security
	})

	// Keep DB connection open for the stores
	shouldCloseDB = false
}
