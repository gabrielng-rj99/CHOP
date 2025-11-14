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

	token, err := GenerateJWT(user.ID, username, role)
	if err != nil {
		log.Printf("Erro ao gerar JWT: %v", err)
		respondError(w, http.StatusInternalServerError, "Erro ao gerar token")
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Login successful",
		Data: map[string]interface{}{
			"token":        token,
			"user_id":      user.ID,
			"username":     username,
			"role":         role,
			"display_name": displayName,
		},
	})
}
