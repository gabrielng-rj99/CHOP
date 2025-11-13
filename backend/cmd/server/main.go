package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"Contracts-Manager/backend/database"
	"Contracts-Manager/backend/domain"
	"Contracts-Manager/backend/store"

	"github.com/google/uuid"
)

type Server struct {
	userStore      *store.UserStore
	contractStore  *store.ContractStore
	clientStore    *store.ClientStore
	dependentStore *store.DependentStore
	categoryStore  *store.CategoryStore
	lineStore      *store.LineStore
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			respondError(w, http.StatusUnauthorized, "Invalid authorization header")
			return
		}

		// TODO: Validate token properly
		// For now, we just check if token exists
		token := parts[1]
		if token == "" {
			respondError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		next(w, r)
	}
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, ErrorResponse{Error: message})
}

func getIDFromPath(r *http.Request, prefix string) string {
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(path, "/")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

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

	token := uuid.New().String()

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Login successful",
		Data: map[string]interface{}{
			"token":        token,
			"user_id":      user.ID,
			"username":     user.Username,
			"role":         user.Role,
			"display_name": user.DisplayName,
		},
	})
}

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
	username := getIDFromPath(r, "/api/users/")

	if username == "" {
		respondError(w, http.StatusBadRequest, "Username required")
		return
	}

	switch r.Method {
	case http.MethodPut:
		s.handleUpdateUser(w, r, username)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, username string) {
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
		if err := s.userStore.EditUserRole("admin", username, req.Role); err != nil {
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User blocked successfully"})
}

func (s *Server) handleUserUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "User unlocked successfully"})
}

// ============= CLIENT HANDLERS =============

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListClients(w, r)
	case http.MethodPost:
		s.handleCreateClient(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.clientStore.GetAllClients()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: clients})
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var client domain.Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	client.Status = "ativo"

	id, err := s.clientStore.CreateClient(client)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, SuccessResponse{
		Message: "Client created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleClientByID(w http.ResponseWriter, r *http.Request) {
	clientID := getIDFromPath(r, "/api/clients/")

	if clientID == "" {
		respondError(w, http.StatusBadRequest, "Client ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetClient(w, r, clientID)
	case http.MethodPut:
		s.handleUpdateClient(w, r, clientID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request, clientID string) {
	client, err := s.clientStore.GetClientByID(clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Client not found")
		} else {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: client})
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request, clientID string) {
	var client domain.Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	client.ID = clientID

	if err := s.clientStore.UpdateClient(client); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Client updated successfully"})
}

func (s *Server) handleClientArchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Client ID required")
		return
	}

	clientID := parts[0]

	if err := s.clientStore.ArchiveClient(clientID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Client archived successfully"})
}

func (s *Server) handleClientUnarchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Client ID required")
		return
	}

	clientID := parts[0]

	if err := s.clientStore.UnarchiveClient(clientID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Client unarchived successfully"})
}

// ============= DEPENDENT HANDLERS =============

func (s *Server) handleClientDependents(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Client ID required")
		return
	}

	clientID := parts[0]

	switch r.Method {
	case http.MethodGet:
		s.handleListDependents(w, r, clientID)
	case http.MethodPost:
		s.handleCreateDependent(w, r, clientID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListDependents(w http.ResponseWriter, r *http.Request, clientID string) {
	dependents, err := s.dependentStore.GetDependentsByClientID(clientID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: dependents})
}

func (s *Server) handleCreateDependent(w http.ResponseWriter, r *http.Request, clientID string) {
	var dependent domain.Dependent
	if err := json.NewDecoder(r.Body).Decode(&dependent); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	dependent.ClientID = clientID
	dependent.Status = "ativo"

	id, err := s.dependentStore.CreateDependent(dependent)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, SuccessResponse{
		Message: "Dependent created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleDependentByID(w http.ResponseWriter, r *http.Request) {
	dependentID := getIDFromPath(r, "/api/dependents/")

	if dependentID == "" {
		respondError(w, http.StatusBadRequest, "Dependent ID required")
		return
	}

	switch r.Method {
	case http.MethodPut:
		s.handleUpdateDependent(w, r, dependentID)
	case http.MethodDelete:
		s.handleDeleteDependent(w, r, dependentID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleUpdateDependent(w http.ResponseWriter, r *http.Request, dependentID string) {
	var dependent domain.Dependent
	if err := json.NewDecoder(r.Body).Decode(&dependent); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	dependent.ID = dependentID

	if err := s.dependentStore.UpdateDependent(dependent); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Dependent updated successfully"})
}

func (s *Server) handleDeleteDependent(w http.ResponseWriter, r *http.Request, dependentID string) {
	if err := s.dependentStore.DeleteDependent(dependentID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Dependent deleted successfully"})
}

// ============= CONTRACT HANDLERS =============

func (s *Server) handleContracts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListContracts(w, r)
	case http.MethodPost:
		s.handleCreateContract(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListContracts(w http.ResponseWriter, r *http.Request) {
	contracts, err := s.contractStore.GetAllContracts()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: contracts})
}

func (s *Server) handleCreateContract(w http.ResponseWriter, r *http.Request) {
	var contract domain.Contract
	if err := json.NewDecoder(r.Body).Decode(&contract); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	id, err := s.contractStore.CreateContract(contract)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, SuccessResponse{
		Message: "Contract created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleContractByID(w http.ResponseWriter, r *http.Request) {
	contractID := getIDFromPath(r, "/api/contracts/")

	if contractID == "" {
		respondError(w, http.StatusBadRequest, "Contract ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetContract(w, r, contractID)
	case http.MethodPut:
		s.handleUpdateContract(w, r, contractID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleGetContract(w http.ResponseWriter, r *http.Request, contractID string) {
	contract, err := s.contractStore.GetContractByID(contractID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Contract not found")
		} else {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: contract})
}

func (s *Server) handleUpdateContract(w http.ResponseWriter, r *http.Request, contractID string) {
	var contract domain.Contract
	if err := json.NewDecoder(r.Body).Decode(&contract); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	contract.ID = contractID

	if err := s.contractStore.UpdateContract(contract); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Contract updated successfully"})
}

func (s *Server) handleContractArchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/contracts/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Contract ID required")
		return
	}

	contractID := parts[0]

	// Archive contract by deleting it (or you can add an archived_at field)
	if err := s.contractStore.DeleteContract(contractID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Contract archived successfully"})
}

func (s *Server) handleContractUnarchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Contract unarchive not implemented"})
}

// ============= CATEGORY HANDLERS =============

func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListCategories(w, r)
	case http.MethodPost:
		s.handleCreateCategory(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListCategories(w http.ResponseWriter, r *http.Request) {
	categories, err := s.categoryStore.GetAllCategories()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: categories})
}

func (s *Server) handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	category := domain.Category{Name: req.Name}

	id, err := s.categoryStore.CreateCategory(category)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, SuccessResponse{
		Message: "Category created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleCategoryByID(w http.ResponseWriter, r *http.Request) {
	categoryID := getIDFromPath(r, "/api/categories/")

	if categoryID == "" {
		respondError(w, http.StatusBadRequest, "Category ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetCategory(w, r, categoryID)
	case http.MethodPut:
		s.handleUpdateCategory(w, r, categoryID)
	case http.MethodDelete:
		s.handleDeleteCategory(w, r, categoryID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleGetCategory(w http.ResponseWriter, r *http.Request, categoryID string) {
	category, err := s.categoryStore.GetCategoryByID(categoryID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Category not found")
		} else {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: category})
}

func (s *Server) handleUpdateCategory(w http.ResponseWriter, r *http.Request, categoryID string) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	category := domain.Category{
		ID:   categoryID,
		Name: req.Name,
	}

	if err := s.categoryStore.UpdateCategory(category); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Category updated successfully"})
}

func (s *Server) handleDeleteCategory(w http.ResponseWriter, r *http.Request, categoryID string) {
	if err := s.categoryStore.DeleteCategory(categoryID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Category deleted successfully"})
}

func (s *Server) handleCategoryLines(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/categories/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Category ID required")
		return
	}

	categoryID := parts[0]

	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	lines, err := s.lineStore.GetLinesByCategoryID(categoryID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: lines})
}

// ============= LINE HANDLERS =============

func (s *Server) handleLines(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListLines(w, r)
	case http.MethodPost:
		s.handleCreateLine(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListLines(w http.ResponseWriter, r *http.Request) {
	lines, err := s.lineStore.GetAllLines()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: lines})
}

func (s *Server) handleCreateLine(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Line       string `json:"line"`
		CategoryID string `json:"category_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	line := domain.Line{
		Line:       req.Line,
		CategoryID: req.CategoryID,
	}

	id, err := s.lineStore.CreateLine(line)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, SuccessResponse{
		Message: "Line created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleLineByID(w http.ResponseWriter, r *http.Request) {
	lineID := getIDFromPath(r, "/api/lines/")

	if lineID == "" {
		respondError(w, http.StatusBadRequest, "Line ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetLine(w, r, lineID)
	case http.MethodPut:
		s.handleUpdateLine(w, r, lineID)
	case http.MethodDelete:
		s.handleDeleteLine(w, r, lineID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleGetLine(w http.ResponseWriter, r *http.Request, lineID string) {
	line, err := s.lineStore.GetLineByID(lineID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Line not found")
		} else {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: line})
}

func (s *Server) handleUpdateLine(w http.ResponseWriter, r *http.Request, lineID string) {
	var req struct {
		Line string `json:"line"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get existing line to preserve category_id
	existingLine, err := s.lineStore.GetLineByID(lineID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Line not found")
		return
	}

	line := domain.Line{
		ID:         lineID,
		Line:       req.Line,
		CategoryID: existingLine.CategoryID,
	}

	if err := s.lineStore.UpdateLine(line); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Line updated successfully"})
}

func (s *Server) handleDeleteLine(w http.ResponseWriter, r *http.Request, lineID string) {
	if err := s.lineStore.DeleteLine(lineID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Line deleted successfully"})
}

// ============= HEALTH HANDLER =============

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// ============= ROUTER SETUP =============

func (s *Server) setupRoutes() {
	// Health check
	http.HandleFunc("/health", corsMiddleware(s.handleHealth))

	// Auth
	http.HandleFunc("/api/login", corsMiddleware(s.handleLogin))

	// Users
	http.HandleFunc("/api/users", corsMiddleware(s.authMiddleware(s.handleUsers)))
	http.HandleFunc("/api/users/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/block") {
			s.handleUserBlock(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unlock") {
			s.handleUserUnlock(w, r)
		} else {
			s.handleUserByUsername(w, r)
		}
	})))

	// Clients
	http.HandleFunc("/api/clients", corsMiddleware(s.authMiddleware(s.handleClients)))
	http.HandleFunc("/api/clients/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/archive") {
			s.handleClientArchive(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
			s.handleClientUnarchive(w, r)
		} else if strings.Contains(r.URL.Path, "/dependents") {
			s.handleClientDependents(w, r)
		} else {
			s.handleClientByID(w, r)
		}
	})))

	// Dependents
	http.HandleFunc("/api/dependents/", corsMiddleware(s.authMiddleware(s.handleDependentByID)))

	// Contracts
	http.HandleFunc("/api/contracts", corsMiddleware(s.authMiddleware(s.handleContracts)))
	http.HandleFunc("/api/contracts/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/archive") {
			s.handleContractArchive(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/unarchive") {
			s.handleContractUnarchive(w, r)
		} else {
			s.handleContractByID(w, r)
		}
	})))

	// Categories
	http.HandleFunc("/api/categories", corsMiddleware(s.authMiddleware(s.handleCategories)))
	http.HandleFunc("/api/categories/", corsMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/lines") {
			s.handleCategoryLines(w, r)
		} else {
			s.handleCategoryByID(w, r)
		}
	})))

	// Lines
	http.HandleFunc("/api/lines", corsMiddleware(s.authMiddleware(s.handleLines)))
	http.HandleFunc("/api/lines/", corsMiddleware(s.authMiddleware(s.handleLineByID)))
}

// ============= MAIN =============

func main() {
	db, err := database.ConnectDB()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()

	server := &Server{
		userStore:      store.NewUserStore(db),
		contractStore:  store.NewContractStore(db),
		clientStore:    store.NewClientStore(db),
		dependentStore: store.NewDependentStore(db),
		categoryStore:  store.NewCategoryStore(db),
		lineStore:      store.NewLineStore(db),
	}

	server.setupRoutes()

	fmt.Println("Server running on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
