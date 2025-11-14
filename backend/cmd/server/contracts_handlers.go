package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"Contracts-Manager/backend/domain"
)

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
