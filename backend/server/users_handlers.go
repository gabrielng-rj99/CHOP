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
	"Open-Generic-Hub/backend/store"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// ============= USER HANDLERS =============

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListUsers(w, r)
	case http.MethodPost:
		s.handleCreateUser(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.userStore.ListUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get admin info for audit
	claims, err := getClaimsFromRequest(r, s.userStore)
	if err != nil {
		log.Printf("Erro ao extrair claims do JWT: %v", err)
		respondError(w, http.StatusUnauthorized, "Token inválido ou não fornecido")
		return
	}

	// Validate role is provided
	if req.Role == "" {
		respondError(w, http.StatusBadRequest, "Role is required. Must be 'user', 'admin', or 'root'")
		return
	}

	// Only root users can create other root users
	if req.Role == "root" && claims.Role != "root" {
		log.Printf("🚫 Acesso negado: %s (role: %s) tentou criar usuário root", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas usuários root podem criar outros usuários root")
		return
	}

	id, err := s.userStore.CreateUser(req.Username, req.DisplayName, req.Password, req.Role)
	if err != nil {
		// Log failed attempt
		errMsg := err.Error()
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "create",
			Entity:        "user",
			EntityID:      "unknown",
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      nil,
			NewValue:      nil,
			Status:        "error",
			ErrorMessage:  &errMsg,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Log successful creation
	newUserData := map[string]interface{}{
		"id":           id,
		"username":     req.Username,
		"display_name": req.DisplayName,
		"role":         req.Role,
	}
	s.auditStore.LogOperation(store.AuditLogRequest{
		Operation:     "create",
		Entity:        "user",
		EntityID:      id,
		AdminID:       &claims.UserID,
		AdminUsername: &claims.Username,
		OldValue:      nil,
		NewValue:      newUserData,
		Status:        "success",
		ErrorMessage:  nil,
		IPAddress:     getIPAddress(r),
		UserAgent:     getUserAgent(r),
		RequestMethod: getRequestMethod(r),
		RequestPath:   getRequestPath(r),
	})

	respondJSON(w, http.StatusCreated, SuccessResponse{
		Message: "User created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleUserByUsername(w http.ResponseWriter, r *http.Request) {
	log.Printf("handleUserByUsername: method=%s, path=%s", r.Method, r.URL.Path)
	username := getIDFromPath(r, "/api/users/")
	log.Printf("Extracted username: '%s'", username)

	if username == "" {
		log.Printf("ERROR: Username is empty after extraction")
		respondError(w, http.StatusBadRequest, "Username required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetUser(w, r, username)
	case http.MethodPut:
		s.handleUpdateUser(w, r, username)
	case http.MethodDelete:
		log.Printf("DELETE request for user: %s", username)

		claims, err := getClaimsFromRequest(r, s.userStore)
		if err != nil {
			log.Printf("Erro ao extrair claims do JWT: %v", err)
			respondError(w, http.StatusUnauthorized, "Token inválido ou não fornecido")
			return
		}

		if claims.Role != "root" {
			log.Printf("Tentativa de deletar usuário %s por %s com role %s - acesso negado", username, claims.Username, claims.Role)
			respondError(w, http.StatusForbidden, "Apenas root pode deletar usuários")
			return
		}

		log.Printf("DELETE request autorizado para %s (role: %s) deletando usuário: %s", claims.Username, claims.Role, username)

		// Get user data before deleting for audit
		users, _ := s.userStore.GetUsersByName(username)
		var oldUserData map[string]interface{}
		var userID string
		if len(users) > 0 {
			userID = users[0].ID
			oldUserData = map[string]interface{}{
				"id":       users[0].ID,
				"username": users[0].Username,
				"role":     users[0].Role,
			}
		}

		if err := s.userStore.DeleteUser(claims.UserID, claims.Username, username); err != nil {
			log.Printf("Error deleting user %s: %v", username, err)
			errMsg := err.Error()
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "delete",
				Entity:        "user",
				EntityID:      userID,
				AdminID:       &claims.UserID,
				AdminUsername: &claims.Username,
				OldValue:      oldUserData,
				NewValue:      nil,
				Status:        "error",
				ErrorMessage:  &errMsg,
				IPAddress:     getIPAddress(r),
				UserAgent:     getUserAgent(r),
				RequestMethod: getRequestMethod(r),
				RequestPath:   getRequestPath(r),
			})
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Log successful deletion
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "delete",
			Entity:        "user",
			EntityID:      userID,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      oldUserData,
			NewValue:      nil,
			Status:        "success",
			ErrorMessage:  nil,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})

		log.Printf("User %s deleted successfully by %s", username, claims.Username)
		respondJSON(w, http.StatusOK, SuccessResponse{Message: "User deleted successfully"})
	default:
		log.Printf("Method not allowed: %s", r.Method)
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, username string) {
	claims, err := getClaimsFromRequest(r, s.userStore)
	if err != nil {
		log.Printf("Erro ao extrair claims do JWT: %v", err)
		respondError(w, http.StatusUnauthorized, "Token inválido ou não fornecido")
		return
	}

	var req struct {
		Username    string `json:"username,omitempty"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password,omitempty"`
		Role        string `json:"role,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get user data before updating for audit (MUST be before any changes)
	users, _ := s.userStore.GetUsersByName(username)
	var oldUserData map[string]interface{}
	var userID string
	if len(users) > 0 {
		userID = users[0].ID
		oldUserData = map[string]interface{}{
			"username":     users[0].Username,
			"display_name": users[0].DisplayName,
			"role":         users[0].Role,
		}
	} else {
		// If user not found, cannot proceed
		respondError(w, http.StatusNotFound, "Usuário não encontrado")
		return
	}

	// === VERIFICAÇÕES DE SEGURANÇA ANTES DE QUALQUER OPERAÇÃO ===
	isUpdatingSelf := claims.Username == username

	// Buscar role do usuário alvo
	targetUserRole := ""
	if users[0].Role != nil {
		targetUserRole = *users[0].Role
	}

	// REGRA 1: Apenas root pode alterar dados de outros usuários root
	if !isUpdatingSelf && targetUserRole == "root" && claims.Role != "root" {
		log.Printf("SEGURANÇA: Tentativa de %s (role: %s) alterar dados do usuário root %s - NEGADO", claims.Username, claims.Role, username)
		respondError(w, http.StatusForbidden, "Apenas root pode alterar dados de outros usuários root")
		return
	}

	// REGRA 2: Admin não pode alterar senha de outros usuários (apenas a própria)
	if req.Password != "" && !isUpdatingSelf && claims.Role != "root" {
		log.Printf("SEGURANÇA: Tentativa de %s (role: %s) alterar senha de %s - NEGADO", claims.Username, claims.Role, username)
		respondError(w, http.StatusForbidden, "Você só pode alterar sua própria senha. Apenas root pode alterar senhas de outros usuários")
		return
	}

	// REGRA 3: Admin não pode alterar display_name de outros admin ou root
	if req.DisplayName != "" && !isUpdatingSelf && claims.Role != "root" && (targetUserRole == "admin" || targetUserRole == "root") {
		log.Printf("SEGURANÇA: Tentativa de %s (role: %s) alterar display_name de %s (role: %s) - NEGADO", claims.Username, claims.Role, username, targetUserRole)
		respondError(w, http.StatusForbidden, "Você não tem permissão para alterar dados deste usuário")
		return
	}

	// Update username if provided and different from current
	if req.Username != "" && req.Username != username {
		if claims.Role != "root" {
			log.Printf("Tentativa de alterar username por %s com role %s - acesso negado", claims.Username, claims.Role)
			respondError(w, http.StatusForbidden, "Apenas root pode alterar username de usuários")
			return
		}
		if err := s.userStore.UpdateUsername(username, req.Username); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Update username variable for subsequent operations
		username = req.Username
	}

	if req.DisplayName != "" {
		if err := s.userStore.EditUserDisplayName(username, req.DisplayName); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if req.Password != "" {
		if err := s.userStore.EditUserPassword(username, req.Password); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if req.Role != "" {
		if claims.Role != "root" {
			log.Printf("SEGURANÇA: Tentativa de alterar role por %s com role %s - acesso negado", claims.Username, claims.Role)
			respondError(w, http.StatusForbidden, "Apenas root pode alterar role de usuários")
			return
		}
		if err := s.userStore.EditUserRole(claims.Username, username, req.Role); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Get updated user data for audit - reflect actual changes
	newUserData := map[string]interface{}{}

	// Username: use new username if changed, otherwise keep old
	if req.Username != "" && req.Username != oldUserData["username"] {
		newUserData["username"] = req.Username
	} else {
		newUserData["username"] = oldUserData["username"]
	}

	// Display name: use new if changed, otherwise keep old
	if req.DisplayName != "" {
		newUserData["display_name"] = req.DisplayName
	} else {
		newUserData["display_name"] = oldUserData["display_name"]
	}

	// Role: use new if changed, otherwise keep old
	if req.Role != "" {
		newUserData["role"] = req.Role
	} else {
		newUserData["role"] = oldUserData["role"]
	}

	// Password: mark as changed if provided
	if req.Password != "" {
		newUserData["password_changed"] = true
	}

	// Log successful update
	s.auditStore.LogOperation(store.AuditLogRequest{
		Operation:     "update",
		Entity:        "user",
		EntityID:      userID,
		AdminID:       &claims.UserID,
		AdminUsername: &claims.Username,
		OldValue:      oldUserData,
		NewValue:      newUserData,
		Status:        "success",
		ErrorMessage:  nil,
		IPAddress:     getIPAddress(r),
		UserAgent:     getUserAgent(r),
		RequestMethod: getRequestMethod(r),
		RequestPath:   getRequestPath(r),
	})

	// Se o usuário alterou a própria senha, avisar que será deslogado
	if isUpdatingSelf && req.Password != "" {
		respondJSON(w, http.StatusOK, SuccessResponse{
			Message: "Senha atualizada com sucesso. Você será deslogado e precisará fazer login novamente.",
			Data: map[string]interface{}{
				"password_changed": true,
				"logout_required":  true,
			},
		})
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User updated successfully"})
}

func (s *Server) handleUserBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	claims, err := getClaimsFromRequest(r, s.userStore)
	if err != nil {
		log.Printf("Erro ao extrair claims do JWT: %v", err)
		respondError(w, http.StatusUnauthorized, "Token inválido ou não fornecido")
		return
	}

	if claims.Role != "root" && claims.Role != "admin" {
		log.Printf("Tentativa de bloquear usuário por %s com role %s - acesso negado", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas admin ou root podem bloquear usuários")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Username required")
		return
	}

	username := parts[0]

	// Get user data before blocking for audit
	users, _ := s.userStore.GetUsersByName(username)
	var userID string
	var displayName string
	if len(users) > 0 {
		userID = users[0].ID
		if users[0].DisplayName != nil {
			displayName = *users[0].DisplayName
		}
	} else {
		respondError(w, http.StatusNotFound, "Usuário não encontrado")
		return
	}

	if err := s.userStore.BlockUser(username); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "user",
			EntityID:      userID,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      map[string]interface{}{"status": "active", "username": username},
			NewValue:      map[string]interface{}{"status": "blocked", "action": "block_user", "username": username, "display_name": displayName},
			Status:        "failed",
			ErrorMessage:  &errMsg,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Log successful block
	s.auditStore.LogOperation(store.AuditLogRequest{
		Operation:     "update",
		Entity:        "user",
		EntityID:      userID,
		AdminID:       &claims.UserID,
		AdminUsername: &claims.Username,
		OldValue:      map[string]interface{}{"status": "active", "username": username},
		NewValue:      map[string]interface{}{"status": "blocked", "action": "block_user", "username": username, "display_name": displayName},
		Status:        "success",
		IPAddress:     getIPAddress(r),
		UserAgent:     getUserAgent(r),
		RequestMethod: getRequestMethod(r),
		RequestPath:   getRequestPath(r),
	})

	log.Printf("User %s bloqueado por %s", username, claims.Username)
	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User blocked successfully"})
}

func (s *Server) handleUserUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	claims, err := getClaimsFromRequest(r, s.userStore)
	if err != nil {
		log.Printf("Erro ao extrair claims do JWT: %v", err)
		respondError(w, http.StatusUnauthorized, "Token inválido ou não fornecido")
		return
	}

	if claims.Role != "root" && claims.Role != "admin" {
		log.Printf("Tentativa de desbloquear usuário por %s com role %s - acesso negado", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas admin ou root podem desbloquear usuários")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Username required")
		return
	}

	username := parts[0]

	// Get user data before unlocking for audit
	users, _ := s.userStore.GetUsersByName(username)
	var userID string
	var displayName string
	if len(users) > 0 {
		userID = users[0].ID
		if users[0].DisplayName != nil {
			displayName = *users[0].DisplayName
		}
	} else {
		respondError(w, http.StatusNotFound, "Usuário não encontrado")
		return
	}

	if err := s.userStore.UnlockUser(username); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "user",
			EntityID:      userID,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      map[string]interface{}{"status": "locked", "username": username},
			NewValue:      map[string]interface{}{"status": "unlocked", "action": "unlock_user", "username": username, "display_name": displayName},
			Status:        "failed",
			ErrorMessage:  &errMsg,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Log successful unlock
	s.auditStore.LogOperation(store.AuditLogRequest{
		Operation:     "update",
		Entity:        "user",
		EntityID:      userID,
		AdminID:       &claims.UserID,
		AdminUsername: &claims.Username,
		OldValue:      map[string]interface{}{"status": "locked", "username": username},
		NewValue:      map[string]interface{}{"status": "unlocked", "action": "unlock_user", "username": username, "display_name": displayName},
		Status:        "success",
		IPAddress:     getIPAddress(r),
		UserAgent:     getUserAgent(r),
		RequestMethod: getRequestMethod(r),
		RequestPath:   getRequestPath(r),
	})

	log.Printf("User %s desbloqueado por %s", username, claims.Username)
	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User unlocked successfully"})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request, username string) {
	// Middleware already ensures Admin/Root or verified Auth, but routes.go wraps this in AdminOnlyMiddleware.
	// So only Admin/Root can call this.

	users, err := s.userStore.GetUsersByName(username)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if len(users) == 0 {
		respondError(w, http.StatusNotFound, "Usuário não encontrado")
		return
	}

	// Return the first match (username is unique)
	respondJSON(w, http.StatusOK, SuccessResponse{Data: users[0]})
}
