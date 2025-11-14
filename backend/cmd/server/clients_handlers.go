package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"Contracts-Manager/backend/domain"
)

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
