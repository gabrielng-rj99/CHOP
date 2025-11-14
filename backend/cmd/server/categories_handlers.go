package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"Contracts-Manager/backend/domain"
)

// ============= CATEGORY HANDLERS =============

func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListCategories(w, r)
	case http.MethodPost:
		s.handleCreateCategory(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleListCategories(w http.ResponseWriter, r *http.Request) {
	categories, err := s.categoryStore.GetAllCategories()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: categories})
}

func (s *Server) handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	category := domain.Category{Name: req.Name}

	id, err := s.categoryStore.CreateCategory(category)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, SuccessResponse{
		Message: "Category created successfully",
		Data:    map[string]string{"id": id},
	})
}

func (s *Server) handleCategoryByID(w http.ResponseWriter, r *http.Request) {
	categoryID := getIDFromPath(r, "/api/categories/")

	if categoryID == "" {
		respondError(w, http.StatusBadRequest, "Category ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetCategory(w, r, categoryID)
	case http.MethodPut:
		s.handleUpdateCategory(w, r, categoryID)
	case http.MethodDelete:
		s.handleDeleteCategory(w, r, categoryID)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleGetCategory(w http.ResponseWriter, r *http.Request, categoryID string) {
	category, err := s.categoryStore.GetCategoryByID(categoryID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Category not found")
		} else {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: category})
}

func (s *Server) handleUpdateCategory(w http.ResponseWriter, r *http.Request, categoryID string) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	category := domain.Category{
		ID:   categoryID,
		Name: req.Name,
	}

	if err := s.categoryStore.UpdateCategory(category); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Category updated successfully"})
}

func (s *Server) handleDeleteCategory(w http.ResponseWriter, r *http.Request, categoryID string) {
	if err := s.categoryStore.DeleteCategory(categoryID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Message: "Category deleted successfully"})
}

func (s *Server) handleCategoryLines(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/categories/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Category ID required")
		return
	}

	categoryID := parts[0]

	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	lines, err := s.lineStore.GetLinesByCategoryID(categoryID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: lines})
}
