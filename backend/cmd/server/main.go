// Contracts-Manager/backend/cmd/server/main.go

package main

import (
	"Contracts-Manager/backend/database"
	"Contracts-Manager/backend/domain"
	"Contracts-Manager/backend/store"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

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
	Message string      `json:"message"`
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
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
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

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}

	id, err := s.userStore.CreateUser(req.Username, req.DisplayName, req.Password, "user")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, SuccessResponse{
		Message: "User created successfully",
		Data: map[string]interface{}{
			"id":       id,
			"username": req.Username,
		},
	})
}

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
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	user, err := s.userStore.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	token := uuid.New().String()

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Login successful",
		Data: map[string]interface{}{
			"token":    token,
			"user_id":  user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	users, err := s.userStore.ListUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Users retrieved successfully",
		Data:    users,
	})
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var client domain.Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

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

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	clients, err := s.clientStore.GetAllClients()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Clients retrieved successfully",
		Data:    clients,
	})
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "Client ID is required")
		return
	}

	client, err := s.clientStore.GetClientByID(id)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Client retrieved successfully",
		Data:    client,
	})
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var client domain.Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if err := s.clientStore.UpdateClient(client); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Client updated successfully",
	})
}

func (s *Server) handleArchiveClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "Client ID is required")
		return
	}

	if err := s.clientStore.ArchiveClient(id); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Client archived successfully",
	})
}

func (s *Server) handleCreateContract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var contract domain.Contract
	if err := json.NewDecoder(r.Body).Decode(&contract); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
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

func (s *Server) handleListContracts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	contracts, err := s.contractStore.GetAllContracts()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Contracts retrieved successfully",
		Data:    contracts,
	})
}

func (s *Server) handleGetContract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "Contract ID is required")
		return
	}

	contract, err := s.contractStore.GetContractByID(id)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Contract retrieved successfully",
		Data:    contract,
	})
}

func (s *Server) handleUpdateContract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var contract domain.Contract
	if err := json.NewDecoder(r.Body).Decode(&contract); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if err := s.contractStore.UpdateContract(contract); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Contract updated successfully",
	})
}

func (s *Server) handleArchiveContract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "Contract ID is required")
		return
	}

	if err := s.contractStore.DeleteContract(id); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Contract archived successfully",
	})
}

func (s *Server) handleCreateDependent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var dependent domain.Dependent
	if err := json.NewDecoder(r.Body).Decode(&dependent); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

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

func (s *Server) handleListDependents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		respondError(w, http.StatusBadRequest, "Client ID is required")
		return
	}

	dependents, err := s.dependentStore.GetDependentsByClientID(clientID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Dependents retrieved successfully",
		Data:    dependents,
	})
}

func (s *Server) handleUpdateDependent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var dependent domain.Dependent
	if err := json.NewDecoder(r.Body).Decode(&dependent); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if err := s.dependentStore.UpdateDependent(dependent); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Dependent updated successfully",
	})
}

func (s *Server) handleDeleteDependent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "Dependent ID is required")
		return
	}

	if err := s.dependentStore.DeleteDependent(id); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Dependent deleted successfully",
	})
}

func (s *Server) handleListCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	categories, err := s.categoryStore.GetAllCategories()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Categories retrieved successfully",
		Data:    categories,
	})
}

func (s *Server) handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	category := domain.Category{
		Name: req.Name,
	}

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

func (s *Server) handleListLines(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	lines, err := s.lineStore.GetAllLines()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{
		Message: "Lines retrieved successfully",
		Data:    lines,
	})
}

func (s *Server) handleCreateLine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Line       string `json:"line"`
		CategoryID string `json:"category_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

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

	http.HandleFunc("/health", corsMiddleware(server.handleHealth))
	http.HandleFunc("/api/register", corsMiddleware(server.handleRegister))
	http.HandleFunc("/api/login", corsMiddleware(server.handleLogin))

	http.HandleFunc("/api/users", corsMiddleware(server.authMiddleware(server.handleListUsers)))

	http.HandleFunc("/api/clients", corsMiddleware(server.authMiddleware(server.handleListClients)))
	http.HandleFunc("/api/clients/create", corsMiddleware(server.authMiddleware(server.handleCreateClient)))
	http.HandleFunc("/api/clients/get", corsMiddleware(server.authMiddleware(server.handleGetClient)))
	http.HandleFunc("/api/clients/update", corsMiddleware(server.authMiddleware(server.handleUpdateClient)))
	http.HandleFunc("/api/clients/archive", corsMiddleware(server.authMiddleware(server.handleArchiveClient)))

	http.HandleFunc("/api/contracts", corsMiddleware(server.authMiddleware(server.handleListContracts)))
	http.HandleFunc("/api/contracts/create", corsMiddleware(server.authMiddleware(server.handleCreateContract)))
	http.HandleFunc("/api/contracts/get", corsMiddleware(server.authMiddleware(server.handleGetContract)))
	http.HandleFunc("/api/contracts/update", corsMiddleware(server.authMiddleware(server.handleUpdateContract)))
	http.HandleFunc("/api/contracts/archive", corsMiddleware(server.authMiddleware(server.handleArchiveContract)))

	http.HandleFunc("/api/dependents", corsMiddleware(server.authMiddleware(server.handleListDependents)))
	http.HandleFunc("/api/dependents/create", corsMiddleware(server.authMiddleware(server.handleCreateDependent)))
	http.HandleFunc("/api/dependents/update", corsMiddleware(server.authMiddleware(server.handleUpdateDependent)))
	http.HandleFunc("/api/dependents/delete", corsMiddleware(server.authMiddleware(server.handleDeleteDependent)))

	http.HandleFunc("/api/categories", corsMiddleware(server.authMiddleware(server.handleListCategories)))
	http.HandleFunc("/api/categories/create", corsMiddleware(server.authMiddleware(server.handleCreateCategory)))

	http.HandleFunc("/api/lines", corsMiddleware(server.authMiddleware(server.handleListLines)))
	http.HandleFunc("/api/lines/create", corsMiddleware(server.authMiddleware(server.handleCreateLine)))

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
