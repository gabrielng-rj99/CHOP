package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
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

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	dependent.ClientID = clientID
	dependent.Status = "ativo"

	id, err := s.dependentStore.CreateDependent(dependent)
	if err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(dependent)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "create",
				Entity:        "dependent",
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

	// Log successful creation
	if claims != nil {
		dependent.ID = id
		newValueJSON, _ := json.Marshal(dependent)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "create",
			Entity:        "dependent",
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

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldDependent, _ := s.dependentStore.GetDependentByID(dependentID)
	oldValueJSON, _ := json.Marshal(oldDependent)

	dependent.ID = dependentID

	if err := s.dependentStore.UpdateDependent(dependent); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(dependent)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "dependent",
				EntityID:      dependentID,
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

	// Log successful update
	if claims != nil {
		newValueJSON, _ := json.Marshal(dependent)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "dependent",
			EntityID:      dependentID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Dependent updated successfully"})
}

func (s *Server) handleDeleteDependent(w http.ResponseWriter, r *http.Request, dependentID string) {
	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldDependent, _ := s.dependentStore.GetDependentByID(dependentID)
	oldValueJSON, _ := json.Marshal(oldDependent)

	if err := s.dependentStore.DeleteDependent(dependentID); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "delete",
				Entity:        "dependent",
				EntityID:      dependentID,
				AdminID:       &claims.UserID,
				AdminUsername: &claims.Username,
				OldValue:      bytesToStringPtr(oldValueJSON),
				NewValue:      nil,
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

	// Log successful deletion
	if claims != nil {
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "delete",
			Entity:        "dependent",
			EntityID:      dependentID,
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			OldValue:      bytesToStringPtr(oldValueJSON),
			NewValue:      nil,
			Status:        "success",
			IPAddress:     getIPAddress(r),
			UserAgent:     getUserAgent(r),
			RequestMethod: getRequestMethod(r),
			RequestPath:   getRequestPath(r),
		})
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Dependent deleted successfully"})
}
