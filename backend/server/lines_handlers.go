package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
)

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

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	line := domain.Line{
		Line:       req.Line,
		CategoryID: req.CategoryID,
	}

	id, err := s.lineStore.CreateLine(line)
	if err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(line)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "create",
				Entity:        "line",
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
		line.ID = id
		newValueJSON, _ := json.Marshal(line)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "create",
			Entity:        "line",
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

	// Check for archive/unarchive endpoints
	if strings.HasSuffix(r.URL.Path, "/archive") {
		if r.Method == http.MethodPost {
			s.handleArchiveLine(w, r, lineID)
			return
		}
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if strings.HasSuffix(r.URL.Path, "/unarchive") {
		if r.Method == http.MethodPost {
			s.handleUnarchiveLine(w, r, lineID)
			return
		}
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
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

	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get existing line to preserve category_id and for audit
	existingLine, err := s.lineStore.GetLineByID(lineID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Line not found")
		return
	}

	oldValueJSON, _ := json.Marshal(existingLine)

	line := domain.Line{
		ID:         lineID,
		Line:       req.Line,
		CategoryID: existingLine.CategoryID,
	}

	if err := s.lineStore.UpdateLine(line); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			newValueJSON, _ := json.Marshal(line)
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "update",
				Entity:        "line",
				EntityID:      lineID,
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
		newValueJSON, _ := json.Marshal(line)
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "line",
			EntityID:      lineID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Line updated successfully"})
}

func (s *Server) handleDeleteLine(w http.ResponseWriter, r *http.Request, lineID string) {
	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldLine, _ := s.lineStore.GetLineByID(lineID)
	oldValueJSON, _ := json.Marshal(oldLine)

	if err := s.lineStore.DeleteLine(lineID); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "delete",
				Entity:        "line",
				EntityID:      lineID,
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
			Entity:        "line",
			EntityID:      lineID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Line deleted successfully"})
}

func (s *Server) handleArchiveLine(w http.ResponseWriter, r *http.Request, lineID string) {
	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldLine, _ := s.lineStore.GetLineByID(lineID)
	oldValueJSON, _ := json.Marshal(oldLine)

	if err := s.lineStore.ArchiveLine(lineID); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "archive",
				Entity:        "line",
				EntityID:      lineID,
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
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "archive",
			Entity:        "line",
			EntityID:      lineID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Line archived successfully"})
}

func (s *Server) handleUnarchiveLine(w http.ResponseWriter, r *http.Request, lineID string) {
	claims, _ := ValidateJWT(extractTokenFromHeader(r), s.userStore)

	// Get old value for audit
	oldLine, _ := s.lineStore.GetLineByID(lineID)
	oldValueJSON, _ := json.Marshal(oldLine)

	if err := s.lineStore.UnarchiveLine(lineID); err != nil {
		// Log failed attempt
		errMsg := err.Error()
		if claims != nil {
			s.auditStore.LogOperation(store.AuditLogRequest{
				Operation:     "unarchive",
				Entity:        "line",
				EntityID:      lineID,
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
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "unarchive",
			Entity:        "line",
			EntityID:      lineID,
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

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Line unarchived successfully"})
}
