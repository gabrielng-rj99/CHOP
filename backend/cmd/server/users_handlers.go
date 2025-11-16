package main

import (
	"Contracts-Manager/backend/store"
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

		if claims.Role != "full_admin" {
			log.Printf("Tentativa de deletar usuário %s por %s com role %s - acesso negado", username, claims.Username, claims.Role)
			respondError(w, http.StatusForbidden, "Apenas full_admin pode deletar usuários")
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
		DisplayName string `json:"display_name"`
		Password    string `json:"password,omitempty"`
		Role        string `json:"role,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get user data before updating for audit
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
		if claims.Role != "full_admin" {
			log.Printf("Tentativa de alterar role por %s com role %s - acesso negado", claims.Username, claims.Role)
			respondError(w, http.StatusForbidden, "Apenas full_admin pode alterar role de usuários")
			return
		}
		if err := s.userStore.EditUserRole(claims.Username, username, req.Role); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Get updated user data for audit
	newUserData := map[string]interface{}{
		"username": username,
	}
	if req.DisplayName != "" {
		newUserData["display_name"] = req.DisplayName
	}
	if req.Role != "" {
		newUserData["role"] = req.Role
	}
	if req.Password != "" {
		newUserData["password"] = "***REDACTED***"
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

	if claims.Role != "full_admin" && claims.Role != "admin" {
		log.Printf("Tentativa de bloquear usuário por %s com role %s - acesso negado", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas admin ou full_admin podem bloquear usuários")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Username required")
		return
	}

	username := parts[0]

	if err := s.userStore.BlockUser(username); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		blockAction := "blocked"
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "user",
			EntityID:      username,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      nil,
			NewValue:      &blockAction,
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

	// Log successful block
	blockAction := "User blocked"
	s.auditStore.LogOperation(store.AuditLogRequest{
		Operation:     "update",
		Entity:        "user",
		EntityID:      username,
		AdminID:       &claims.UserID,
		AdminUsername: &claims.Username,
		OldValue:      nil,
		NewValue:      &blockAction,
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

	if claims.Role != "full_admin" && claims.Role != "admin" {
		log.Printf("Tentativa de desbloquear usuário por %s com role %s - acesso negado", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Apenas admin ou full_admin podem desbloquear usuários")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Username required")
		return
	}

	username := parts[0]

	if err := s.userStore.UnlockUser(username); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		unlockAction := "unlocked"
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "user",
			EntityID:      username,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      nil,
			NewValue:      &unlockAction,
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

	// Log successful unlock
	unlockAction := "User unlocked"
	s.auditStore.LogOperation(store.AuditLogRequest{
		Operation:     "update",
		Entity:        "user",
		EntityID:      username,
		AdminID:       &claims.UserID,
		AdminUsername: &claims.Username,
		OldValue:      nil,
		NewValue:      &unlockAction,
		Status:        "success",
		IPAddress:     getIPAddress(r),
		UserAgent:     getUserAgent(r),
		RequestMethod: getRequestMethod(r),
		RequestPath:   getRequestPath(r),
	})

	log.Printf("User %s desbloqueado por %s", username, claims.Username)
	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User unlocked successfully"})
}
