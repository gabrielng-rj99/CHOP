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
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"Open-Generic-Hub/backend/store"
)

// DashboardConfigRequest represents the dashboard configuration settings
type DashboardConfigRequest struct {
	ShowBirthdays          bool `json:"show_birthdays"`
	BirthdaysDaysAhead     int  `json:"birthdays_days_ahead"`
	ShowRecentActivity     bool `json:"show_recent_activity"`
	RecentActivityCount    int  `json:"recent_activity_count"`
	ShowStatistics         bool `json:"show_statistics"`
	ShowExpiringAgreements bool `json:"show_expiring_agreements"`
	ExpiringDaysAhead      int  `json:"expiring_days_ahead"`
	ShowQuickActions       bool `json:"show_quick_actions"`
}

// HandleDashboardConfigRoute routes GET/PUT requests for dashboard config
func (s *Server) HandleDashboardConfigRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.HandleGetDashboardConfig(w, r)
	case http.MethodPut:
		s.HandleUpdateDashboardConfig(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// HandleGetDashboardConfig handles GET /api/system-config/dashboard
func (s *Server) HandleGetDashboardConfig(w http.ResponseWriter, r *http.Request) {
	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Admin+ can view dashboard config
	if claims.Role != "root" && claims.Role != "admin" {
		respondError(w, http.StatusForbidden, "Acesso negado")
		return
	}

	// Get system settings
	settings, err := s.settingsStore.GetSystemSettings()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao carregar configurações")
		return
	}

	// Build response with defaults
	response := DashboardConfigRequest{
		ShowBirthdays:          true,
		BirthdaysDaysAhead:     7,
		ShowRecentActivity:     true,
		RecentActivityCount:    10,
		ShowStatistics:         true,
		ShowExpiringAgreements: true,
		ExpiringDaysAhead:      30,
		ShowQuickActions:       true,
	}

	// Parse settings from database
	for key, value := range settings {
		switch key {
		case "dashboard.show_birthdays":
			response.ShowBirthdays = value == "true"
		case "dashboard.birthdays_days_ahead":
			if val, err := strconv.Atoi(value); err == nil {
				response.BirthdaysDaysAhead = val
			}
		case "dashboard.show_recent_activity":
			response.ShowRecentActivity = value == "true"
		case "dashboard.recent_activity_count":
			if val, err := strconv.Atoi(value); err == nil {
				response.RecentActivityCount = val
			}
		case "dashboard.show_statistics":
			response.ShowStatistics = value == "true"
		case "dashboard.show_expiring_agreements":
			response.ShowExpiringAgreements = value == "true"
		case "dashboard.expiring_days_ahead":
			if val, err := strconv.Atoi(value); err == nil {
				response.ExpiringDaysAhead = val
			}
		case "dashboard.show_quick_actions":
			response.ShowQuickActions = value == "true"
		}
	}

	respondJSON(w, http.StatusOK, response)
}

// HandleUpdateDashboardConfig handles PUT /api/system-config/dashboard
func (s *Server) HandleUpdateDashboardConfig(w http.ResponseWriter, r *http.Request) {
	// Extract and validate JWT
	tokenString := extractTokenFromHeader(r)
	if tokenString == "" {
		respondError(w, http.StatusUnauthorized, "Token não fornecido")
		return
	}

	claims, err := ValidateJWT(tokenString, s.userStore)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Token inválido ou expirado")
		return
	}

	// Admin+ can update dashboard config
	if claims.Role != "root" && claims.Role != "admin" {
		log.Printf("🚫 User %s (role: %s) denied access to update dashboard config", claims.Username, claims.Role)
		respondError(w, http.StatusForbidden, "Acesso negado")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	// Parse request
	var req DashboardConfigRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate values
	if req.BirthdaysDaysAhead < 1 || req.BirthdaysDaysAhead > 90 {
		respondError(w, http.StatusBadRequest, "Dias de aniversariantes deve estar entre 1 e 90")
		return
	}

	if req.RecentActivityCount < 5 || req.RecentActivityCount > 50 {
		respondError(w, http.StatusBadRequest, "Número de atividades recentes deve estar entre 5 e 50")
		return
	}

	if req.ExpiringDaysAhead < 7 || req.ExpiringDaysAhead > 180 {
		respondError(w, http.StatusBadRequest, "Dias de vencimento deve estar entre 7 e 180")
		return
	}

	// Save settings
	settingsToSave := map[string]string{
		"dashboard.show_birthdays":           strconv.FormatBool(req.ShowBirthdays),
		"dashboard.birthdays_days_ahead":     strconv.Itoa(req.BirthdaysDaysAhead),
		"dashboard.show_recent_activity":     strconv.FormatBool(req.ShowRecentActivity),
		"dashboard.recent_activity_count":    strconv.Itoa(req.RecentActivityCount),
		"dashboard.show_statistics":          strconv.FormatBool(req.ShowStatistics),
		"dashboard.show_expiring_agreements": strconv.FormatBool(req.ShowExpiringAgreements),
		"dashboard.expiring_days_ahead":      strconv.Itoa(req.ExpiringDaysAhead),
		"dashboard.show_quick_actions":       strconv.FormatBool(req.ShowQuickActions),
	}

	for key, value := range settingsToSave {
		if err := s.settingsStore.UpdateSystemSetting(key, value); err != nil {
			log.Printf("❌ Error saving dashboard setting %s: %v", key, err)
			respondError(w, http.StatusInternalServerError, "Erro ao salvar configurações")
			return
		}
	}

	log.Printf("✅ User %s updated dashboard config", claims.Username)

	// Log to audit
	if s.auditStore != nil {
		userAgent := r.UserAgent()
		method := r.Method
		path := r.URL.Path
		s.auditStore.LogOperation(store.AuditLogRequest{
			Operation:     "update",
			Entity:        "dashboard_config",
			EntityID:      "dashboard",
			AdminID:       &claims.UserID,
			AdminUsername: &claims.Username,
			NewValue:      req,
			Status:        "success",
			IPAddress:     getIPAddress(r),
			UserAgent:     &userAgent,
			RequestMethod: &method,
			RequestPath:   &path,
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Configurações do dashboard salvas com sucesso",
	})
}
