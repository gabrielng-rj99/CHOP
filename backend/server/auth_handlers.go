package server

import (
	"Contracts-Manager/backend/store"
	"encoding/json"
	"log"
	"net/http"
)

// ============= AUTH HANDLERS =============

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := s.userStore.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		// Log failed login attempt
		errMsg := err.Error()
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "login",
			Entity:        "auth",
			EntityID:      req.Username,
			AdminID:       nil,
			AdminUsername: &req.Username,
			OldValue:      nil,
			NewValue: map[string]interface{}{
				"method": "password",
				"result": "failed",
				"reason": errMsg,
			},
			Status:        "failed",
			ErrorMessage:  &errMsg,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	role := ""
	if user.Role != nil {
		role = *user.Role
	}

	displayName := ""
	if user.DisplayName != nil {
		displayName = *user.DisplayName
	}

	accessToken, err := GenerateJWT(user)
	if err != nil {
		log.Printf("Erro ao gerar access token: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao gerar token")
		return
	}

	refreshToken, err := GenerateRefreshToken(user)
	if err != nil {
		log.Printf("Erro ao gerar refresh token: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao gerar refresh token")
		return
	}

	// Log successful login
	s.auditStore.LogOperation(store.AuditLogRequest{
		Operation:     "login",
		Entity:        "auth",
		EntityID:      user.ID,
		AdminID:       &user.ID,
		AdminUsername: &username,
		OldValue:      nil,
		NewValue: map[string]interface{}{
			"method": "password",
			"result": "success",
		},
		Status:        "success",
		ErrorMessage:  nil,
		IPAddress:     getIPAddress(r),
		UserAgent:     getUserAgent(r),
		RequestMethod: getRequestMethod(r),
		RequestPath:   getRequestPath(r),
	})

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Login successful",
		Data: map[string]interface{}{
			"token":         accessToken,
			"refresh_token": refreshToken,
			"user_id":       user.ID,
			"username":      username,
			"role":          role,
			"display_name":  displayName,
		},
	})
}

// ============= REFRESH TOKEN HANDLER =============

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	claims, err := ValidateRefreshToken(req.RefreshToken, s.userStore)
	if err != nil {
		// Log failed token refresh
		errMsg := err.Error()
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "login",
			Entity:        "auth",
			EntityID:      "",
			AdminID:       nil,
			AdminUsername: nil,
			OldValue:      nil,
			NewValue: map[string]interface{}{
				"method": "token",
				"result": "failed",
				"reason": errMsg,
			},
			Status:        "failed",
			ErrorMessage:  &errMsg,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
		respondError(w, http.StatusUnauthorized, "Refresh token inválido ou expirado")
		return
	}

	user, err := s.userStore.GetUserByID(claims.UserID)
	if err != nil || user == nil {
		errMsg := "Usuário não encontrado"
		if err != nil {
			errMsg = err.Error()
		}
		// Try to get username from user if available
		var usernamePtr *string
		if user != nil && user.Username != nil {
			usernamePtr = user.Username
		}
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "login",
			Entity:        "auth",
			EntityID:      claims.UserID,
			AdminID:       nil,
			AdminUsername: usernamePtr,
			OldValue:      nil,
			NewValue: map[string]interface{}{
				"method": "token",
				"result": "failed",
				"reason": errMsg,
			},
			Status:        "failed",
			ErrorMessage:  &errMsg,
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
		respondError(w, http.StatusUnauthorized, "Usuário não encontrado")
		return
	}

	accessToken, err := GenerateJWT(user)
	if err != nil {
		log.Printf("Erro ao gerar novo access token: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao gerar novo token")
		return
	}

	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	// Log successful token refresh
	s.auditStore.LogOperation(store.AuditLogRequest{
		Operation:     "login",
		Entity:        "auth",
		EntityID:      user.ID,
		AdminID:       &user.ID,
		AdminUsername: &username,
		OldValue:      nil,
		NewValue: map[string]interface{}{
			"method": "token",
			"result": "success",
		},
		Status:        "success",
		ErrorMessage:  nil,
		IPAddress:     getIPAddress(r),
		UserAgent:     getUserAgent(r),
		RequestMethod: getRequestMethod(r),
		RequestPath:   getRequestPath(r),
	})

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Token renovado com sucesso",
		Data: map[string]interface{}{
			"token": accessToken,
		},
	})
}
