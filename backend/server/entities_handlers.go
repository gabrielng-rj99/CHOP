/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	domain "Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
)

// ============= CLIENT HANDLERS =============

func (s *Server) handleEntities(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListEntities(w, r)
	case http.MethodPost:
		s.handleCreateEntity(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListEntities(w http.ResponseWriter, r *http.Request) {
	// Check if requesting with contract stats
	includeStats := r.URL.Query().Get("include_stats") == "true"

	entities, err := s.entityStore.GetAllEntitiesIncludingArchived()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if includeStats {
		// Get contract stats for all entities
		statsMap, err := s.agreementStore.GetAgreementStatsForAllEntities()
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Create response with entities and their stats
		type EntityWithStats struct {
			domain.Entity
			ActiveAgreements   int `json:"active_agreements"`
			ExpiredAgreements  int `json:"expired_agreements"`
			ArchivedAgreements int `json:"archived_agreements"`
		}

		entitiesWithStats := make([]EntityWithStats, 0, len(entities))
		for _, entity := range entities {
			cws := EntityWithStats{Entity: entity}
			if stats, ok := statsMap[entity.ID]; ok {
				cws.ActiveAgreements = stats.ActiveAgreements
				cws.ExpiredAgreements = stats.ExpiredAgreements
				cws.ArchivedAgreements = stats.ArchivedAgreements
			}
			entitiesWithStats = append(entitiesWithStats, cws)
		}

		respondJSON(w, http.StatusOK, SuccessResponse{Data: entitiesWithStats})
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: entities})
}

func (s *Server) handleCreateEntity(w http.ResponseWriter, r *http.Request) {
	var entity domain.Entity
	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Status will be auto-calculated by CreateEntity based on active agreements
	// Ignore any status sent from frontend
	entity.Status = ""

	id, err := s.entityStore.CreateEntity(entity)
	if err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(entity)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "create",
				Entity:        "entity",
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
		entity.ID = id
		newValueJSON, _ := json.Marshal(entity)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "create",
			Entity:        "entity",
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
		Message: "Entity created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleEntityByID(w http.ResponseWriter, r *http.Request) {
	entityID := getIDFromPath(r, "/api/entities/")

	if entityID == "" {
		respondError(w, http.StatusBadRequest, "Entity ID required")
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(entityID); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid Entity ID format")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetEntity(w, r, entityID)
	case http.MethodPut:
		s.handleUpdateEntity(w, r, entityID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleGetEntity(w http.ResponseWriter, r *http.Request, entityID string) {
	entity, err := s.entityStore.GetEntityByID(entityID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Entity not found")
		} else {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: entity})
}

func (s *Server) handleUpdateEntity(w http.ResponseWriter, r *http.Request, entityID string) {
	var entity domain.Entity
	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldEntity, _ := s.entityStore.GetEntityByID(entityID)
	oldValueJSON, _ := json.Marshal(oldEntity)

	entity.ID = entityID
	// Status will be auto-calculated by UpdateEntity based on active agreements
	// Ignore any status sent from frontend
	entity.Status = ""

	if err := s.entityStore.UpdateEntity(entity); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(entity)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "entity",
				EntityID:      entityID,
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

	// Update entity status based on active agreements
	if err := s.entityStore.UpdateEntityStatus(entityID); err != nil {
		// Log warning but don't fail the request
		// This is a non-critical operation
	}

	// Log successful update
	if claims != nil {
		newValueJSON, _ := json.Marshal(entity)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "entity",
			EntityID:      entityID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Entity updated successfully"})
}

func (s *Server) handleEntityArchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/entities/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Entity ID required")
		return
	}

	entityID := parts[0]
	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldEntity, _ := s.entityStore.GetEntityByID(entityID)
	oldValueJSON, _ := json.Marshal(oldEntity)

	if err := s.entityStore.ArchiveEntity(entityID); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "entity",
				EntityID:      entityID,
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
		newEntity, _ := s.entityStore.GetEntityByID(entityID)
		newValueJSON, _ := json.Marshal(newEntity)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "entity",
			EntityID:      entityID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Entity archived successfully"})
}

func (s *Server) handleEntityUnarchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/entities/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Entity ID required")
		return
	}

	entityID := parts[0]
	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldEntity, _ := s.entityStore.GetEntityByID(entityID)
	oldValueJSON, _ := json.Marshal(oldEntity)

	if err := s.entityStore.UnarchiveEntity(entityID); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "entity",
				EntityID:      entityID,
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
		newEntity, _ := s.entityStore.GetEntityByID(entityID)
		newValueJSON, _ := json.Marshal(newEntity)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "entity",
			EntityID:      entityID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Entity unarchived successfully"})
}
