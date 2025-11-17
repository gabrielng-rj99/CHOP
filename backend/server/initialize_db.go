package server

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"Contracts-Manager/backend/config"
	"Contracts-Manager/backend/database"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// InitializeDatabaseRequest represents the database initialization payload
type InitializeDatabaseRequest struct {
	DatabaseHost     string `json:"database_host"`
	DatabasePort     string `json:"database_port"`
	DatabaseName     string `json:"database_name"`
	DatabaseUser     string `json:"database_user"`
	DatabasePassword string `json:"database_password"`
}

// InitializeDatabaseResponse represents the response from database initialization
type InitializeDatabaseResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Errors  []string    `json:"errors,omitempty"`
	Config  interface{} `json:"config,omitempty"`
}

var globalDB *sql.DB

// SetGlobalDB sets the global database connection (called after initialization)
func SetGlobalDB(db *sql.DB) {
	globalDB = db
}

// GetGlobalDB returns the global database connection
func GetGlobalDB() *sql.DB {
	return globalDB
}

// HandleInitializeDatabase initializes the database with schema
// POST /api/initialize/database - Creates database and loads schema
func (s *Server) HandleInitializeDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req InitializeDatabaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InitializeDatabaseResponse{
			Success: false,
			Message: "Invalid request payload",
			Errors:  []string{err.Error()},
		})
		return
	}

	var errors []string

	// Validate input
	if req.DatabaseHost == "" {
		errors = append(errors, "database_host is required")
	}
	if req.DatabasePort == "" {
		errors = append(errors, "database_port is required")
	}
	if req.DatabaseName == "" {
		errors = append(errors, "database_name is required")
	}
	if req.DatabaseUser == "" {
		errors = append(errors, "database_user is required")
	}
	if req.DatabasePassword == "" {
		errors = append(errors, "database_password is required")
	}

	if len(errors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InitializeDatabaseResponse{
			Success: false,
			Message: "Validation failed",
			Errors:  errors,
		})
		return
	}

	// Update config with new database settings
	cfg := config.GetConfig()
	cfg.Database.Host = req.DatabaseHost
	cfg.Database.Port = req.DatabasePort
	cfg.Database.Name = req.DatabaseName
	cfg.Database.User = req.DatabaseUser
	cfg.Database.Password = req.DatabasePassword

	// Set environment variables for connection
	os.Setenv("APP_DATABASE_PASSWORD", req.DatabasePassword)

	// Try to connect with new configuration
	db, err := database.ConnectDB()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InitializeDatabaseResponse{
			Success: false,
			Message: "Failed to connect to database",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Load and execute schema
	schemaPath := cfg.Paths.SchemaFile
	schemaSQL, err := os.ReadFile(schemaPath)
	if err != nil {
		db.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InitializeDatabaseResponse{
			Success: false,
			Message: "Failed to read schema file",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Execute schema
	_, err = db.Exec(string(schemaSQL))
	if err != nil {
		db.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InitializeDatabaseResponse{
			Success: false,
			Message: "Failed to initialize database schema",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Store connection globally
	SetGlobalDB(db)

	log.Printf("✅ Database initialized: %s@%s:%s/%s", req.DatabaseUser, req.DatabaseHost, req.DatabasePort, req.DatabaseName)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(InitializeDatabaseResponse{
		Success: true,
		Message: "Database initialized successfully",
		Config: map[string]interface{}{
			"host": req.DatabaseHost,
			"port": req.DatabasePort,
			"name": req.DatabaseName,
			"user": req.DatabaseUser,
		},
	})
}
