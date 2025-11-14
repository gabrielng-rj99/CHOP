package main

import (
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

	id, err := s.userStore.CreateUser(req.Username, req.DisplayName, req.Password, req.Role)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

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

		claims, err := getClaimsFromRequest(r)
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
		if err := s.userStore.DeleteUser(claims.UserID, claims.Username, username); err != nil {
			log.Printf("Error deleting user %s: %v", username, err)
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("User %s deleted successfully by %s", username, claims.Username)
		respondJSON(w, http.StatusOK, SuccessResponse{Message: "User deleted successfully"})
	default:
		log.Printf("Method not allowed: %s", r.Method)
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, username string) {
	claims, err := getClaimsFromRequest(r)
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User updated successfully"})
}

func (s *Server) handleUserBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	claims, err := getClaimsFromRequest(r)
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
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	log.Printf("User %s bloqueado por %s", username, claims.Username)
	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User blocked successfully"})
}

func (s *Server) handleUserUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	claims, err := getClaimsFromRequest(r)
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
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	log.Printf("User %s desbloqueado por %s", username, claims.Username)
	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User unlocked successfully"})
}
