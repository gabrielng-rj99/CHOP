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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"Open-Generic-Hub/backend/config"
)

// DeployConfigRequest represents the configuration payload from the deploy panel
type DeployConfigRequest struct {
	// Server configuration
	ServerHost string `json:"server_host,omitempty"`
	ServerPort string `json:"server_port,omitempty"`

	// Database configuration
	DatabaseHost     string `json:"database_host,omitempty"`
	DatabasePort     string `json:"database_port,omitempty"`
	DatabaseName     string `json:"database_name,omitempty"`
	DatabaseUser     string `json:"database_user,omitempty"`
	DatabasePassword string `json:"database_password,omitempty"`
	DatabaseSSLMode  string `json:"database_ssl_mode,omitempty"`

	// JWT configuration
	JWTSecretKey             string `json:"jwt_secret_key,omitempty"`
	JWTExpirationTime        int    `json:"jwt_expiration_time,omitempty"`
	JWTRefreshExpirationTime int    `json:"jwt_refresh_expiration_time,omitempty"`

	// Security configuration
	SecurityPasswordMinLength        int  `json:"security_password_min_length,omitempty"`
	SecurityPasswordRequireUppercase bool `json:"security_password_require_uppercase,omitempty"`
	SecurityPasswordRequireLowercase bool `json:"security_password_require_lowercase,omitempty"`
	SecurityPasswordRequireNumbers   bool `json:"security_password_require_numbers,omitempty"`
	SecurityPasswordRequireSpecial   bool `json:"security_password_require_special,omitempty"`
	SecurityMaxFailedAttempts        int  `json:"security_max_failed_attempts,omitempty"`
	SecurityLockoutDurationMinutes   int  `json:"security_lockout_duration_minutes,omitempty"`

	// Application environment
	AppEnv string `json:"app_env,omitempty"`

	// Deploy signature (optional, for security verification)
	DeployToken string `json:"deploy_token,omitempty"`
}

// DeployConfigResponse represents the response from the configuration endpoint
type DeployConfigResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Errors  []string    `json:"errors,omitempty"`
	Config  interface{} `json:"config,omitempty"`
}

// DeployStatus represents the deployment status
type DeployStatus struct {
	Status       string `json:"status"`
	Message      string `json:"message"`
	Timestamp    string `json:"timestamp"`
	Environment  string `json:"environment"`
	Version      string `json:"version"`
	ConfigLoaded bool   `json:"config_loaded"`
}

// HandleDeployConfig handles the dynamic configuration endpoint
// POST /api/deploy/config - Updates server configuration at runtime
func (s *Server) HandleDeployConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify deploy token (if set in environment)
	deployToken := os.Getenv("DEPLOY_TOKEN")
	if deployToken != "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+deployToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(DeployConfigResponse{
				Success: false,
				Message: "Unauthorized: Invalid or missing deploy token",
			})
			return
		}
	}

	var req DeployConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(DeployConfigResponse{
			Success: false,
			Message: "Invalid request payload",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Get current config
	currentCfg := config.GetConfig()

	// Create updated configuration
	updatedCfg := &config.Config{
		Server:   currentCfg.Server,
		Database: currentCfg.Database,
		JWT:      currentCfg.JWT,
		Security: currentCfg.Security,
		App:      currentCfg.App,
	}

	var errors []string
	var warnings []string

	// Update server configuration if provided
	if req.ServerPort != "" {
		updatedCfg.Server.Port = req.ServerPort
	}
	if req.ServerHost != "" {
		updatedCfg.Server.Host = req.ServerHost
	}

	// Update database configuration if provided
	if req.DatabaseHost != "" {
		updatedCfg.Database.Host = req.DatabaseHost
	}
	if req.DatabasePort != "" {
		updatedCfg.Database.Port = req.DatabasePort
	}
	if req.DatabaseName != "" {
		updatedCfg.Database.Name = req.DatabaseName
	}
	if req.DatabaseUser != "" {
		updatedCfg.Database.User = req.DatabaseUser
	}
	if req.DatabasePassword != "" {
		updatedCfg.Database.Password = req.DatabasePassword
		// Also set environment variable for database connection
		os.Setenv("APP_DATABASE_PASSWORD", req.DatabasePassword)
	}
	if req.DatabaseSSLMode != "" {
		updatedCfg.Database.SSLMode = req.DatabaseSSLMode
	}

	// Update JWT configuration if provided
	if req.JWTSecretKey != "" {
		updatedCfg.JWT.SecretKey = req.JWTSecretKey
		// Also set environment variable for JWT secret
		os.Setenv("APP_JWT_SECRET_KEY", req.JWTSecretKey)
	}
	if req.JWTExpirationTime > 0 {
		warnings = append(warnings, "Set JWT_EXPIRATION_TIME environment variable.")
	}
	if req.JWTRefreshExpirationTime > 0 {
		warnings = append(warnings, "Set JWT_REFRESH_EXPIRATION_TIME environment variable.")
	}

	// Update security configuration if provided
	if req.SecurityPasswordMinLength > 0 {
		updatedCfg.Security.PasswordMinLength = req.SecurityPasswordMinLength
	}
	if req.SecurityPasswordRequireUppercase {
		updatedCfg.Security.PasswordUppercase = req.SecurityPasswordRequireUppercase
	}
	if req.SecurityPasswordRequireLowercase {
		updatedCfg.Security.PasswordLowercase = req.SecurityPasswordRequireLowercase
	}
	if req.SecurityPasswordRequireNumbers {
		updatedCfg.Security.PasswordNumbers = req.SecurityPasswordRequireNumbers
	}
	if req.SecurityPasswordRequireSpecial {
		updatedCfg.Security.PasswordSpecial = req.SecurityPasswordRequireSpecial
	}
	if req.SecurityMaxFailedAttempts > 0 {
		updatedCfg.Security.MaxFailedAttempts = req.SecurityMaxFailedAttempts
	}
	if req.SecurityLockoutDurationMinutes > 0 {
		warnings = append(warnings, "Set LOCKOUT_DURATION environment variable.")
	}

	// Update application environment if provided
	if req.AppEnv != "" {
		updatedCfg.App.Env = req.AppEnv
		os.Setenv("APP_ENV", req.AppEnv)
	}

	// Note: Config updates now happen via environment variables
	// The application will need to restart to pick up changes

	// Log configuration update
	log.Printf("✅ Configuration updated via deploy panel (env: %s)", updatedCfg.App.Env)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(DeployConfigResponse{
		Success: len(errors) == 0,
		Message: "Configuration updated successfully",
		Errors:  errors,
		Config: map[string]interface{}{
			"server": map[string]interface{}{
				"host": updatedCfg.Server.Host,
				"port": updatedCfg.Server.Port,
			},
			"database": map[string]interface{}{
				"host": updatedCfg.Database.Host,
				"port": updatedCfg.Database.Port,
				"name": updatedCfg.Database.Name,
				"user": updatedCfg.Database.User,
			},
			"environment": updatedCfg.App.Env,
		},
	})
}

// HandleDeployStatus handles the deploy status endpoint
// GET /api/deploy/status - Returns current deployment status
func (s *Server) HandleDeployStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := config.GetConfig()

	status := DeployStatus{
		Status:       "running",
		Message:      "Application is running and operational",
		Environment:  cfg.App.Env,
		Version:      cfg.App.Version,
		ConfigLoaded: true,
		Timestamp:    fmt.Sprintf("%v", os.Getenv("DEPLOY_TIMESTAMP")),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// HandleDeployValidate validates a configuration without applying it
// POST /api/deploy/validate - Validates configuration payload
func (s *Server) HandleDeployValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DeployConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(DeployConfigResponse{
			Success: false,
			Message: "Invalid request payload",
			Errors:  []string{err.Error()},
		})
		return
	}

	var errors []string

	// Validate database configuration
	if req.DatabasePort != "" && req.DatabasePort != "5432" && req.DatabasePort != "3306" && req.DatabasePort != "65432" {
		// Allow common database ports
		_, err := parsePort(req.DatabasePort)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Invalid database port: %s", req.DatabasePort))
		}
	}

	// Validate server port
	if req.ServerPort != "" {
		_, err := parsePort(req.ServerPort)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Invalid server port: %s", req.ServerPort))
		}
	}

	// Validate JWT secret length
	if req.JWTSecretKey != "" && len(req.JWTSecretKey) < 16 {
		errors = append(errors, "JWT secret key must be at least 16 characters long")
	}

	// Validate password requirements
	if req.SecurityPasswordMinLength > 0 && req.SecurityPasswordMinLength < 8 {
		errors = append(errors, "Password minimum length should be at least 8")
	}

	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if len(errors) > 0 {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(DeployConfigResponse{
		Success: len(errors) == 0,
		Message: "Configuration validation completed",
		Errors:  errors,
	})
}

// HandleDeployConfigDefaults returns current configuration defaults from config.ini
// GET /api/deploy/config/defaults - Returns current server configuration
func (s *Server) HandleDeployConfigDefaults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := config.GetConfig()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"config": map[string]interface{}{
			"server": map[string]interface{}{
				"host": cfg.Server.Host,
				"port": cfg.Server.Port,
			},
			"database": map[string]interface{}{
				"host":     cfg.Database.Host,
				"port":     cfg.Database.Port,
				"name":     cfg.Database.Name,
				"user":     cfg.Database.User,
				"ssl_mode": cfg.Database.SSLMode,
			},
			"jwt": map[string]interface{}{
				"expiration_time":         cfg.JWT.ExpirationTime,
				"refresh_expiration_time": cfg.JWT.RefreshExpirationTime,
				"algorithm":               cfg.JWT.Algorithm,
			},
		},
	})
}

// Helper function to parse and validate port number
func parsePort(portStr string) (int, error) {
	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port number: %s", portStr)
	}
	return port, nil
}
