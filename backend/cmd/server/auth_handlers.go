package main

import (
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
		respondError(w, http.StatusUnauthorized, "Refresh token inválido ou expirado")
		return
	}

	user, err := s.userStore.GetUserByID(claims.UserID)
	if err != nil || user == nil {
		respondError(w, http.StatusUnauthorized, "Usuário não encontrado")
		return
	}

	accessToken, err := GenerateJWT(user)
	if err != nil {
		log.Printf("Erro ao gerar novo access token: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao gerar novo token")
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Token renovado com sucesso",
		Data: map[string]interface{}{
			"token": accessToken,
		},
	})
}
