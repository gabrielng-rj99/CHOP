package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"Contracts-Manager/backend/domain"
	"Contracts-Manager/backend/store"
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
	contracts, err := s.contractStore.GetAllContractsIncludingArchived()
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

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	id, err := s.contractStore.CreateContract(contract)
	if err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(contract)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "create",
				Entity:        "contract",
				EntityID:      "unknown",
				AdminID:       &claims.UserID,
				AdminUsername: &claims.Username,
				OldValue:      nil,
				NewValue:      bytesToStringPtr(newValueJSON),
				Status:        "error",
				ErrorMessage:  &errMsg,
				IPAddress:     getIPAddress(r),
				UserAgent:     getUserAgent(r),
				RequestMethod: getRequestMethod(r),
				RequestPath:   getRequestPath(r),
			})
		}
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Update client status based on active contracts
	if err := s.clientStore.UpdateClientStatus(contract.ClientID); err != nil {
		// Log warning but don't fail the request
		// This is a non-critical operation
	}

	// Update category status based on usage
	contractData, _ := s.contractStore.GetContractByID(id)
	if contractData != nil {
		lineData, _ := s.lineStore.GetLineByID(contractData.LineID)
		if lineData != nil {
			if err := s.categoryStore.UpdateCategoryStatus(lineData.CategoryID); err != nil {
				// Log warning but don't fail the request
			}
		}
	}

	// Log successful creation
	if claims != nil {
		contract.ID = id
		newValueJSON, _ := json.Marshal(contract)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "create",
			Entity:        "contract",
			EntityID:      id,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      nil,
			NewValue:      bytesToStringPtr(newValueJSON),
			Status:        "success",
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
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

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldContract, _ := s.contractStore.GetContractByID(contractID)
	oldValueJSON, _ := json.Marshal(oldContract)

	contract.ID = contractID

	if err := s.contractStore.UpdateContract(contract); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(contract)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "contract",
				EntityID:      contractID,
				AdminID:       &claims.UserID,
				AdminUsername: &claims.Username,
				OldValue:      bytesToStringPtr(oldValueJSON),
				NewValue:      bytesToStringPtr(newValueJSON),
				Status:        "error",
				ErrorMessage:  &errMsg,
				IPAddress:     getIPAddress(r),
				UserAgent:     getUserAgent(r),
				RequestMethod: getRequestMethod(r),
				RequestPath:   getRequestPath(r),
			})
		}
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Update client status based on active contracts
	if err := s.clientStore.UpdateClientStatus(contract.ClientID); err != nil {
		// Log warning but don't fail the request
		// This is a non-critical operation
	}

	// Update category status based on usage
	lineData, _ := s.lineStore.GetLineByID(contract.LineID)
	if lineData != nil {
		if err := s.categoryStore.UpdateCategoryStatus(lineData.CategoryID); err != nil {
			// Log warning but don't fail the request
		}
	}

	// Log successful update
	if claims != nil {
		newValueJSON, _ := json.Marshal(contract)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "contract",
			EntityID:      contractID,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      bytesToStringPtr(oldValueJSON),
			NewValue:      bytesToStringPtr(newValueJSON),
			Status:        "success",
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
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

	// Get contract before archiving to update client status
	oldContract, _ := s.contractStore.GetContractByID(contractID)

	// Archive contract by deleting it (or you can add an archived_at field)
	if err := s.contractStore.DeleteContract(contractID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Update client status based on active contracts
	if oldContract != nil {
		if err := s.clientStore.UpdateClientStatus(oldContract.ClientID); err != nil {
			// Log warning but don't fail the request
			// This is a non-critical operation
		}

		// Update category status based on usage
		lineData, _ := s.lineStore.GetLineByID(oldContract.LineID)
		if lineData != nil {
			if err := s.categoryStore.UpdateCategoryStatus(lineData.CategoryID); err != nil {
				// Log warning but don't fail the request
			}
		}
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
