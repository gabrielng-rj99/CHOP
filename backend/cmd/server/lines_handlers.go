package main

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"Contracts-Manager/backend/domain"
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

func (s *Server) handleLineByID(w http.ResponseWriter, r *http.Request) {
	lineID := getIDFromPath(r, "/api/lines/")

	if lineID == "" {
		respondError(w, http.StatusBadRequest, "Line ID required")
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

	// Get existing line to preserve category_id
	existingLine, err := s.lineStore.GetLineByID(lineID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Line not found")
		return
	}

	line := domain.Line{
		ID:         lineID,
		Line:       req.Line,
		CategoryID: existingLine.CategoryID,
	}

	if err := s.lineStore.UpdateLine(line); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Line updated successfully"})
}

func (s *Server) handleDeleteLine(w http.ResponseWriter, r *http.Request, lineID string) {
	if err := s.lineStore.DeleteLine(lineID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Line deleted successfully"})
}
