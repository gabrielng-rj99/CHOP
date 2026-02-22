/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
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
	"net/http"
	"strconv"
	"time"
)

// DashboardCounts holds aggregated counts for the dashboard.
// This endpoint replaces loading ALL clients + ALL contracts + ALL categories
// just to compute counts on the frontend (which was ~15k+ rows transferred).
type DashboardCounts struct {
	Clients    ClientCounts   `json:"clients"`
	Contracts  ContractCounts `json:"contracts"`
	Categories CategoryCounts `json:"categories"`
}

// ClientCounts holds client status breakdown.
type ClientCounts struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Inactive int `json:"inactive"`
	Archived int `json:"archived"`
}

// ContractCounts holds contract status breakdown.
type ContractCounts struct {
	Total      int `json:"total"`
	Active     int `json:"active"`
	Expiring   int `json:"expiring"`
	Expired    int `json:"expired"`
	NotStarted int `json:"not_started"`
	Archived   int `json:"archived"`
}

// CategoryCounts holds category/subcategory totals.
type CategoryCounts struct {
	Total         int `json:"total"`
	Active        int `json:"active"`
	Archived      int `json:"archived"`
	Subcategories int `json:"subcategories"`
}

// handleDashboardCounts handles GET /api/dashboard/counts
// Returns aggregated counts in a single response using efficient COUNT queries.
// This replaces the old pattern where the Dashboard fetched ALL records just to count them.
//
// Query params:
//   - expiring_days: number of days ahead to consider contracts as "expiring" (default: 30)
func (s *Server) handleDashboardCounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.db == nil {
		respondError(w, http.StatusServiceUnavailable, "Database not available")
		return
	}

	expiringDays := 30
	if d := r.URL.Query().Get("expiring_days"); d != "" {
		if val, err := strconv.Atoi(d); err == nil && val > 0 && val <= 365 {
			expiringDays = val
		}
	}

	counts := DashboardCounts{}

	// ── Client counts (single query) ──
	clientErr := s.db.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'ativo'),
			COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'inativo'),
			COUNT(*) FILTER (WHERE archived_at IS NOT NULL)
		FROM clients
	`).Scan(
		&counts.Clients.Total,
		&counts.Clients.Active,
		&counts.Clients.Inactive,
		&counts.Clients.Archived,
	)
	if clientErr != nil {
		respondError(w, http.StatusInternalServerError, "Failed to count clients: "+clientErr.Error())
		return
	}

	// ── Contract counts (single query) ──
	now := time.Now()
	expiringLimit := now.AddDate(0, 0, expiringDays)

	contractErr := s.db.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE archived_at IS NULL AND start_date <= $1 AND (end_date IS NULL OR end_date > $2)),
			COUNT(*) FILTER (WHERE archived_at IS NULL AND end_date IS NOT NULL AND end_date > $1 AND end_date <= $2),
			COUNT(*) FILTER (WHERE archived_at IS NULL AND end_date IS NOT NULL AND end_date <= $1),
			COUNT(*) FILTER (WHERE archived_at IS NULL AND start_date > $1),
			COUNT(*) FILTER (WHERE archived_at IS NOT NULL)
		FROM contracts
	`, now, expiringLimit).Scan(
		&counts.Contracts.Total,
		&counts.Contracts.Active,
		&counts.Contracts.Expiring,
		&counts.Contracts.Expired,
		&counts.Contracts.NotStarted,
		&counts.Contracts.Archived,
	)
	if contractErr != nil {
		respondError(w, http.StatusInternalServerError, "Failed to count contracts: "+contractErr.Error())
		return
	}

	// ── Category + subcategory counts (two lightweight queries) ──
	catErr := s.db.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE archived_at IS NULL),
			COUNT(*) FILTER (WHERE archived_at IS NOT NULL)
		FROM categories
	`).Scan(
		&counts.Categories.Total,
		&counts.Categories.Active,
		&counts.Categories.Archived,
	)
	if catErr != nil {
		respondError(w, http.StatusInternalServerError, "Failed to count categories: "+catErr.Error())
		return
	}

	subErr := s.db.QueryRow(`
		SELECT COUNT(*) FROM subcategories
	`).Scan(&counts.Categories.Subcategories)
	if subErr != nil {
		respondError(w, http.StatusInternalServerError, "Failed to count subcategories: "+subErr.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: counts})
}

// handleClientCounts handles GET /api/clients/counts
// Returns client status breakdown counts. Used by the Clients page filter buttons
// so they can display counts without loading all client records.
func (s *Server) handleClientCounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.db == nil {
		respondError(w, http.StatusServiceUnavailable, "Database not available")
		return
	}

	var counts ClientCounts
	err := s.db.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'ativo'),
			COUNT(*) FILTER (WHERE archived_at IS NULL AND status = 'inativo'),
			COUNT(*) FILTER (WHERE archived_at IS NOT NULL)
		FROM clients
	`).Scan(
		&counts.Total,
		&counts.Active,
		&counts.Inactive,
		&counts.Archived,
	)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to count clients: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, SuccessResponse{Data: counts})
}
