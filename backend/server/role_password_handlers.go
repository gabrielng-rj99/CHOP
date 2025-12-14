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
	"strings"

	"Open-Generic-Hub/backend/store"
)

// ============================================
// Request/Response Types
// ============================================

// RolePasswordPolicyRequest represents password policy for a role
type RolePasswordPolicyRequest struct {
	MinLength         int  `json:"min_length"`
	RequireUppercase  bool `json:"require_uppercase"`
	RequireLowercase  bool `json:"require_lowercase"`
	RequireNumbers    bool `json:"require_numbers"`
	RequireSpecial    bool `json:"require_special"`
	MaxAge            *int `json:"max_age,omitempty"`             // days before password expires
	PreventReuse      *int `json:"prevent_reuse,omitempty"`       // number of previous passwords to check
	MinChangeInterval *int `json:"min_change_interval,omitempty"` // minimum hours between password changes
}

// RolePasswordPolicyResponse represents password policy in API responses
type RolePasswordPolicyResponse struct {
	ID                string `json:"id"`
	RoleID            string `json:"role_id"`
	RoleName          string `json:"role_name"`
	MinLength         int    `json:"min_length"`
	RequireUppercase  bool   `json:"require_uppercase"`
	RequireLowercase  bool   `json:"require_lowercase"`
	RequireNumbers    bool   `json:"require_numbers"`
	RequireSpecial    bool   `json:"require_special"`
	MaxAge            *int   `json:"max_age,omitempty"`
	PreventReuse      *int   `json:"prevent_reuse,omitempty"`
	MinChangeInterval *int   `json:"min_change_interval,omitempty"`
	IsActive          bool   `json:"is_active"`
}

// ============================================
// Password Policy Handlers
// ============================================

// HandleRolePasswordPoliciesRoute routes GET requests for all role password policies
func (s *Server) HandleRolePasswordPoliciesRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Validate token - Root only
	tokenString := extractTokenFromHeader(r)
	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	if claims.Role != "root" {
		respondError(w, http.StatusForbidden, "Apenas root pode visualizar políticas de senha")
		return
	}

	s.HandleGetAllRolePasswordPolicies(w, r)
}

// HandleRolePasswordPolicyByIDRoute routes GET/PUT requests for a specific role's password policy
func (s *Server) HandleRolePasswordPolicyByIDRoute(w http.ResponseWriter, r *http.Request) {
	// Extract role ID from path: /api/roles/{id}/password-policy
	path := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Role ID required")
		return
	}
	roleID := parts[0]

	// Validate token - Root only
	tokenString := extractTokenFromHeader(r)
	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	if claims.Role != "root" {
		respondError(w, http.StatusForbidden, "Apenas root pode gerenciar políticas de senha")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.HandleGetRolePasswordPolicy(w, r, roleID)
	case http.MethodPut:
		s.HandleUpdateRolePasswordPolicy(w, r, roleID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// HandleGetAllRolePasswordPolicies returns all role password policies
func (s *Server) HandleGetAllRolePasswordPolicies(w http.ResponseWriter, r *http.Request) {
	db := GetGlobalDB()
	if db == nil {
		respondError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	query := `
		SELECT
			rpp.id, rpp.role_id, r.name as role_name,
			rpp.min_length, rpp.require_uppercase, rpp.require_lowercase,
			rpp.require_numbers, rpp.require_special,
			rpp.max_age, rpp.prevent_reuse, rpp.min_change_interval,
			rpp.is_active
		FROM role_password_policies rpp
		JOIN roles r ON rpp.role_id = r.id
		WHERE rpp.is_active = TRUE
		ORDER BY r.priority DESC
	`

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("❌ Error querying password policies: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao buscar políticas de senha")
		return
	}
	defer rows.Close()

	var policies []RolePasswordPolicyResponse
	for rows.Next() {
		var policy RolePasswordPolicyResponse
		var maxAge, preventReuse, minChangeInterval sql.NullInt64

		err := rows.Scan(
			&policy.ID,
			&policy.RoleID,
			&policy.RoleName,
			&policy.MinLength,
			&policy.RequireUppercase,
			&policy.RequireLowercase,
			&policy.RequireNumbers,
			&policy.RequireSpecial,
			&maxAge,
			&preventReuse,
			&minChangeInterval,
			&policy.IsActive,
		)
		if err != nil {
			log.Printf("❌ Error scanning password policy: %v", err)
			continue
		}

		if maxAge.Valid {
			val := int(maxAge.Int64)
			policy.MaxAge = &val
		}
		if preventReuse.Valid {
			val := int(preventReuse.Int64)
			policy.PreventReuse = &val
		}
		if minChangeInterval.Valid {
			val := int(minChangeInterval.Int64)
			policy.MinChangeInterval = &val
		}

		policies = append(policies, policy)
	}

	respondJSON(w, http.StatusOK, policies)
}

// HandleGetRolePasswordPolicy returns password policy for a specific role
func (s *Server) HandleGetRolePasswordPolicy(w http.ResponseWriter, r *http.Request, roleID string) {
	db := GetGlobalDB()
	if db == nil {
		respondError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	// Check if role exists
	var roleName string
	err := db.QueryRow("SELECT name FROM roles WHERE id = $1", roleID).Scan(&roleName)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Role não encontrado")
			return
		}
		log.Printf("❌ Error checking role: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao verificar role")
		return
	}

	query := `
		SELECT
			id, role_id, min_length, require_uppercase, require_lowercase,
			require_numbers, require_special, max_age, prevent_reuse,
			min_change_interval, is_active
		FROM role_password_policies
		WHERE role_id = $1 AND is_active = TRUE
	`

	var policy RolePasswordPolicyResponse
	var maxAge, preventReuse, minChangeInterval sql.NullInt64

	err = db.QueryRow(query, roleID).Scan(
		&policy.ID,
		&policy.RoleID,
		&policy.MinLength,
		&policy.RequireUppercase,
		&policy.RequireLowercase,
		&policy.RequireNumbers,
		&policy.RequireSpecial,
		&maxAge,
		&preventReuse,
		&minChangeInterval,
		&policy.IsActive,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// Return default policy if none exists
			policy = RolePasswordPolicyResponse{
				RoleID:           roleID,
				RoleName:         roleName,
				MinLength:        16,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           nil,
				PreventReuse:     nil,
				IsActive:         false,
			}
			respondJSON(w, http.StatusOK, policy)
			return
		}
		log.Printf("❌ Error querying password policy: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao buscar política de senha")
		return
	}

	policy.RoleName = roleName
	if maxAge.Valid {
		val := int(maxAge.Int64)
		policy.MaxAge = &val
	}
	if preventReuse.Valid {
		val := int(preventReuse.Int64)
		policy.PreventReuse = &val
	}
	if minChangeInterval.Valid {
		val := int(minChangeInterval.Int64)
		policy.MinChangeInterval = &val
	}

	respondJSON(w, http.StatusOK, policy)
}

// HandleUpdateRolePasswordPolicy updates or creates password policy for a role
func (s *Server) HandleUpdateRolePasswordPolicy(w http.ResponseWriter, r *http.Request, roleID string) {
	db := GetGlobalDB()
	if db == nil {
		respondError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	// Get claims for audit
	tokenString := extractTokenFromHeader(r)
	claims, _ := ValidateJWT(tokenString, s.userStore)

	// Check if role exists
	var roleName string
	err := db.QueryRow("SELECT name FROM roles WHERE id = $1", roleID).Scan(&roleName)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Role não encontrado")
			return
		}
		log.Printf("❌ Error checking role: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao verificar role")
		return
	}

	// Parse request
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req RolePasswordPolicyRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate values
	if req.MinLength < 8 || req.MinLength > 128 {
		respondError(w, http.StatusBadRequest, "Tamanho mínimo de senha deve estar entre 8 e 128 caracteres")
		return
	}

	if req.MaxAge != nil && (*req.MaxAge < 1 || *req.MaxAge > 365) {
		respondError(w, http.StatusBadRequest, "Idade máxima da senha deve estar entre 1 e 365 dias")
		return
	}

	if req.PreventReuse != nil && (*req.PreventReuse < 1 || *req.PreventReuse > 24) {
		respondError(w, http.StatusBadRequest, "Prevenção de reuso deve estar entre 1 e 24 senhas anteriores")
		return
	}

	if req.MinChangeInterval != nil && (*req.MinChangeInterval < 1 || *req.MinChangeInterval > 168) {
		respondError(w, http.StatusBadRequest, "Intervalo mínimo de mudança deve estar entre 1 e 168 horas")
		return
	}

	// Get old value for audit
	var oldPolicy *RolePasswordPolicyResponse
	var oldID, oldRoleID string
	var oldMinLen int
	var oldUpper, oldLower, oldNumbers, oldSpecial, oldActive bool
	var oldMaxAge, oldPreventReuse, oldMinChange sql.NullInt64

	queryOld := `
		SELECT id, role_id, min_length, require_uppercase, require_lowercase,
		       require_numbers, require_special, max_age, prevent_reuse,
		       min_change_interval, is_active
		FROM role_password_policies
		WHERE role_id = $1 AND is_active = TRUE
	`
	err = db.QueryRow(queryOld, roleID).Scan(
		&oldID, &oldRoleID, &oldMinLen, &oldUpper, &oldLower,
		&oldNumbers, &oldSpecial, &oldMaxAge, &oldPreventReuse,
		&oldMinChange, &oldActive,
	)
	if err == nil {
		oldPolicy = &RolePasswordPolicyResponse{
			ID:               oldID,
			RoleID:           oldRoleID,
			MinLength:        oldMinLen,
			RequireUppercase: oldUpper,
			RequireLowercase: oldLower,
			RequireNumbers:   oldNumbers,
			RequireSpecial:   oldSpecial,
			IsActive:         oldActive,
		}
		if oldMaxAge.Valid {
			val := int(oldMaxAge.Int64)
			oldPolicy.MaxAge = &val
		}
		if oldPreventReuse.Valid {
			val := int(oldPreventReuse.Int64)
			oldPolicy.PreventReuse = &val
		}
		if oldMinChange.Valid {
			val := int(oldMinChange.Int64)
			oldPolicy.MinChangeInterval = &val
		}
	}

	// Upsert password policy
	query := `
		INSERT INTO role_password_policies (
			role_id, min_length, require_uppercase, require_lowercase,
			require_numbers, require_special, max_age, prevent_reuse,
			min_change_interval, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE)
		ON CONFLICT (role_id, is_active) DO UPDATE SET
			min_length = EXCLUDED.min_length,
			require_uppercase = EXCLUDED.require_uppercase,
			require_lowercase = EXCLUDED.require_lowercase,
			require_numbers = EXCLUDED.require_numbers,
			require_special = EXCLUDED.require_special,
			max_age = EXCLUDED.max_age,
			prevent_reuse = EXCLUDED.prevent_reuse,
			min_change_interval = EXCLUDED.min_change_interval,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id
	`

	var policyID string
	err = db.QueryRow(
		query,
		roleID,
		req.MinLength,
		req.RequireUppercase,
		req.RequireLowercase,
		req.RequireNumbers,
		req.RequireSpecial,
		req.MaxAge,
		req.PreventReuse,
		req.MinChangeInterval,
	).Scan(&policyID)

	if err != nil {
		log.Printf("❌ Error upserting password policy: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao salvar política de senha")
		return
	}

	log.Printf("✅ User %s updated password policy for role %s", claims.Username, roleName)

	// Log to audit
	if s.auditStore != nil {
		userAgent := r.UserAgent()
		method := r.Method
		path := r.URL.Path
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "role_password_policy",
			EntityID:      roleID,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      oldPolicy,
			NewValue:      req,
			Status:        "success",
			IPAddress:     getIPAddress(r),
			UserAgent:     &userAgent,
			RequestMethod: &method,
			RequestPath:   &path,
		})
	}

	response := RolePasswordPolicyResponse{
		ID:                policyID,
		RoleID:            roleID,
		RoleName:          roleName,
		MinLength:         req.MinLength,
		RequireUppercase:  req.RequireUppercase,
		RequireLowercase:  req.RequireLowercase,
		RequireNumbers:    req.RequireNumbers,
		RequireSpecial:    req.RequireSpecial,
		MaxAge:            req.MaxAge,
		PreventReuse:      req.PreventReuse,
		MinChangeInterval: req.MinChangeInterval,
		IsActive:          true,
	}

	respondJSON(w, http.StatusOK, response)
}
