package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"Contracts-Manager/backend/domain"
)

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
