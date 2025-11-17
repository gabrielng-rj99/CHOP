package server

import (
	"Contracts-Manager/backend/database"
	"Contracts-Manager/backend/store"
	"encoding/json"
	"log"
	"net/http"
)

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

// HandleInitializeAdmin handles the admin initialization endpoint
// POST /api/initialize/admin - Creates the root admin user
func (s *Server) HandleInitializeAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	// Validate input
	var errors []string

	if req.DisplayName == "" {
		errors = append(errors, "Display name is required")
	}

	if req.Password == "" {
		errors = append(errors, "Password is required")
	} else if len(req.Password) < 8 {
		errors = append(errors, "Password must be at least 8 characters")
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

	// Connect to database
	db, err := database.ConnectDB()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InitializeAdminResponse{
			Success: false,
			Message: "Failed to connect to database",
			Errors:  []string{err.Error()},
		})
		return
	}
	defer db.Close()

	userStore := store.NewUserStore(db)

	// Default username if not provided
	username := req.Username
	if username == "" {
		username = "root"
	}

	// Create the root admin user
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(InitializeAdminResponse{
		Success:       true,
		Message:       "Root admin user created successfully",
		AdminID:       adminID,
		AdminUsername: username,
		AdminPassword: req.Password,
	})
}
