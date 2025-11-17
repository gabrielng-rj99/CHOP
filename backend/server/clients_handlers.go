package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	domain "Contracts-Manager/backend/domain"
	"Contracts-Manager/backend/store"
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
	// Check if requesting with contract stats
	includeStats := r.URL.Query().Get("include_stats") == "true"

	clients, err := s.clientStore.GetAllClientsIncludingArchived()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if includeStats {
		// Get contract stats for all clients
		statsMap, err := s.contractStore.GetContractStatsForAllClients()
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Create response with clients and their stats
		type ClientWithStats struct {
			domain.Client
			ActiveContracts   int `json:"active_contracts"`
			ExpiredContracts  int `json:"expired_contracts"`
			ArchivedContracts int `json:"archived_contracts"`
		}

		clientsWithStats := make([]ClientWithStats, 0, len(clients))
		for _, client := range clients {
			cws := ClientWithStats{Client: client}
			if stats, ok := statsMap[client.ID]; ok {
				cws.ActiveContracts = stats.ActiveContracts
				cws.ExpiredContracts = stats.ExpiredContracts
				cws.ArchivedContracts = stats.ArchivedContracts
			}
			clientsWithStats = append(clientsWithStats, cws)
		}

		respondJSON(w, http.StatusOK, SuccessResponse{Data: clientsWithStats})
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

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Status will be auto-calculated by CreateClient based on active contracts
	// Ignore any status sent from frontend
	client.Status = ""

	id, err := s.clientStore.CreateClient(client)
	if err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(client)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "create",
				Entity:        "client",
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
		client.ID = id
		newValueJSON, _ := json.Marshal(client)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "create",
			Entity:        "client",
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

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldClient, _ := s.clientStore.GetClientByID(clientID)
	oldValueJSON, _ := json.Marshal(oldClient)

	client.ID = clientID
	// Status will be auto-calculated by UpdateClient based on active contracts
	// Ignore any status sent from frontend
	client.Status = ""

	if err := s.clientStore.UpdateClient(client); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(client)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "client",
				EntityID:      clientID,
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
	if err := s.clientStore.UpdateClientStatus(clientID); err != nil {
		// Log warning but don't fail the request
		// This is a non-critical operation
	}

	// Log successful update
	if claims != nil {
		newValueJSON, _ := json.Marshal(client)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "client",
			EntityID:      clientID,
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
	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldClient, _ := s.clientStore.GetClientByID(clientID)
	oldValueJSON, _ := json.Marshal(oldClient)

	if err := s.clientStore.ArchiveClient(clientID); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "client",
				EntityID:      clientID,
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

	// Log successful archive
	if claims != nil {
		newClient, _ := s.clientStore.GetClientByID(clientID)
		newValueJSON, _ := json.Marshal(newClient)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "client",
			EntityID:      clientID,
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
	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldClient, _ := s.clientStore.GetClientByID(clientID)
	oldValueJSON, _ := json.Marshal(oldClient)

	if err := s.clientStore.UnarchiveClient(clientID); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "client",
				EntityID:      clientID,
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

	// Log successful unarchive
	if claims != nil {
		newClient, _ := s.clientStore.GetClientByID(clientID)
		newValueJSON, _ := json.Marshal(newClient)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "client",
			EntityID:      clientID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Client unarchived successfully"})
}
