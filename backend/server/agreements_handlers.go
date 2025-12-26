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

	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
)

// ============= AGREEMENT HANDLERS =============

func (s *Server) handleAgreements(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListAgreements(w, r)
	case http.MethodPost:
		s.handleCreateAgreement(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListAgreements(w http.ResponseWriter, _ *http.Request) {
	agreements, err := s.agreementStore.GetAllAgreementsIncludingArchived()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: agreements})
}

func (s *Server) handleCreateAgreement(w http.ResponseWriter, r *http.Request) {
	var agreement domain.Agreement
	if err := json.NewDecoder(r.Body).Decode(&agreement); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	id, err := s.agreementStore.CreateAgreement(agreement)
	if err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(agreement)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "create",
				Entity:        "agreement",
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

	// Update entity status based on active agreements
	if err := s.entityStore.UpdateEntityStatus(agreement.EntityID); err != nil {
		// Log warning but don't fail the request
		// This is a non-critical operation
	}

	// Update category status based on usage
	agreementData, _ := s.agreementStore.GetAgreementByID(id)
	if agreementData != nil {
		lineData, _ := s.subcategoryStore.GetSubcategoryByID(agreementData.SubcategoryID)
		if lineData != nil {
			if err := s.categoryStore.UpdateCategoryStatus(lineData.CategoryID); err != nil {
				// Log warning but don't fail the request
			}
		}
	}

	// Log successful creation
	if claims != nil {
		agreement.ID = id
		newValueJSON, _ := json.Marshal(agreement)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "create",
			Entity:        "agreement",
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
		Message: "Agreement created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleAgreementByID(w http.ResponseWriter, r *http.Request) {
	agreementID := getIDFromPath(r, "/api/agreements/")

	if agreementID == "" {
		respondError(w, http.StatusBadRequest, "Agreement ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetAgreement(w, r, agreementID)
	case http.MethodPut:
		s.handleUpdateAgreement(w, r, agreementID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleGetAgreement(w http.ResponseWriter, _ *http.Request, agreementID string) {
	agreement, err := s.agreementStore.GetAgreementByID(agreementID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Agreement not found")
		} else {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: agreement})
}

func (s *Server) handleUpdateAgreement(w http.ResponseWriter, r *http.Request, agreementID string) {
	var agreement domain.Agreement
	if err := json.NewDecoder(r.Body).Decode(&agreement); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldAgreement, _ := s.agreementStore.GetAgreementByID(agreementID)
	oldValueJSON, _ := json.Marshal(oldAgreement)

	agreement.ID = agreementID

	if err := s.agreementStore.UpdateAgreement(agreement); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(agreement)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "agreement",
				EntityID:      agreementID,
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
	if err := s.entityStore.UpdateEntityStatus(agreement.EntityID); err != nil {
		// Log warning but don't fail the request
		// This is a non-critical operation
	}

	// Update category status based on usage
	lineData, _ := s.subcategoryStore.GetSubcategoryByID(agreement.SubcategoryID)
	if lineData != nil {
		if err := s.categoryStore.UpdateCategoryStatus(lineData.CategoryID); err != nil {
			// Log warning but don't fail the request
		}
	}

	// Log successful update
	if claims != nil {
		newValueJSON, _ := json.Marshal(agreement)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "agreement",
			EntityID:      agreementID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Agreement updated successfully"})
}

func (s *Server) handleAgreementArchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/agreements/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Agreement ID required")
		return
	}

	agreementID := parts[0]

	// Get agreement before archiving to update entity status
	oldAgreement, _ := s.agreementStore.GetAgreementByID(agreementID)

	// Archive agreement by deleting it (or you can add an archived_at field)
	if err := s.agreementStore.DeleteAgreement(agreementID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Update entity status based on active agreements
	if oldAgreement != nil {
		if err := s.entityStore.UpdateEntityStatus(oldAgreement.EntityID); err != nil {
			// Log warning but don't fail the request
			// This is a non-critical operation
		}

		// Update category status based on usage
		lineData, _ := s.subcategoryStore.GetSubcategoryByID(oldAgreement.SubcategoryID)
		if lineData != nil {
			if err := s.categoryStore.UpdateCategoryStatus(lineData.CategoryID); err != nil {
				// Log warning but don't fail the request
			}
		}
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Agreement archived successfully"})
}

func (s *Server) handleAgreementUnarchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Agreement unarchive not implemented"})
}
