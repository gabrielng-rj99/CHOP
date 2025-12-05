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
	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleAuditLogs GET /api/audit-logs - lista logs de auditoria com filtros
func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	// Extrair filtros da query string
	query := r.URL.Query()

	var entity *string
	if e := query.Get("entity"); e != "" {
		entity = &e
	}

	var operation *string
	if o := query.Get("operation"); o != "" {
		operation = &o
	}

	var adminID *string
	if a := query.Get("admin_id"); a != "" {
		adminID = &a
	}

	var adminSearch *string
	if as := query.Get("admin_search"); as != "" {
		adminSearch = &as
	}

	var entityID *string
	if ei := query.Get("entity_id"); ei != "" {
		entityID = &ei
	}

	var entitySearch *string
	if es := query.Get("entity_search"); es != "" {
		entitySearch = &es
	}

	var changedData *string
	if cd := query.Get("changed_data"); cd != "" {
		changedData = &cd
	}

	var status *string
	if st := query.Get("status"); st != "" {
		status = &st
	}

	var ipAddress *string
	if ip := query.Get("ip_address"); ip != "" {
		ipAddress = &ip
	}

	// Filtro temporal
	var startDate *time.Time
	var endDate *time.Time

	if startStr := query.Get("start_date"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			startDate = &t
		}
	}

	if endStr := query.Get("end_date"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			endDate = &t
		}
	}

	// Paginação
	limit := 100
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	offset := 0
	if off := query.Get("offset"); off != "" {
		if parsed, err := strconv.Atoi(off); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	filter := store.AuditLogFilter{
		Entity:       entity,
		Operation:    operation,
		AdminID:      adminID,
		AdminSearch:  adminSearch,
		EntityID:     entityID,
		EntitySearch: entitySearch,
		ChangedData:  changedData,
		Status:       status,
		IPAddress:    ipAddress,
		StartDate:    startDate,
		EndDate:      endDate,
		Limit:        limit,
		Offset:       offset,
	}

	logs, err := s.auditStore.ListAuditLogs(filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao buscar logs de auditoria")
		return
	}

	// Enriquecer logs com usernames atuais
	enrichedLogs := s.enrichLogsWithUsernames(logs)

	// Contar total para paginação
	total, err := s.auditStore.CountAuditLogs(filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao contar logs")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data":   enrichedLogs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// handleAuditLogDetail GET /api/audit-logs/{id} - detalhes de um log específico
func (s *Server) handleAuditLogDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	logID := getIDFromPath(r, "/api/audit-logs/")
	if logID == "" {
		respondError(w, http.StatusBadRequest, "ID de log não fornecido")
		return
	}

	log, err := s.auditStore.GetAuditLogByID(logID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Log de auditoria não encontrado")
		return
	}

	// Enriquecer log com username atual
	enrichedLog := s.enrichLogWithUsername(log)

	respondJSON(w, http.StatusOK, enrichedLog)
}

// enrichLogsWithUsernames busca usernames atuais baseados nos admin_ids
func (s *Server) enrichLogsWithUsernames(logs []domain.AuditLog) []domain.AuditLog {
	if len(logs) == 0 {
		return logs
	}

	// Coletar todos os admin_ids únicos
	adminIDs := make(map[string]bool)
	for _, log := range logs {
		if log.AdminID != nil && *log.AdminID != "" {
			adminIDs[*log.AdminID] = true
		}
	}

	// Buscar usernames para cada ID
	usernameCache := make(map[string]string)
	for adminID := range adminIDs {
		user, err := s.userStore.GetUserByID(adminID)
		if err == nil && user != nil && user.Username != nil {
			usernameCache[adminID] = *user.Username
		}
	}

	// Enriquecer logs com usernames atuais
	enrichedLogs := make([]domain.AuditLog, len(logs))
	for i, log := range logs {
		enrichedLogs[i] = log
		if log.AdminID != nil {
			if currentUsername, exists := usernameCache[*log.AdminID]; exists {
				enrichedLogs[i].AdminUsername = &currentUsername
			}
		}
	}

	return enrichedLogs
}

// enrichLogWithUsername busca username atual baseado no admin_id
func (s *Server) enrichLogWithUsername(log *domain.AuditLog) *domain.AuditLog {
	if log == nil {
		return log
	}

	if log.AdminID != nil && *log.AdminID != "" {
		user, err := s.userStore.GetUserByID(*log.AdminID)
		if err == nil && user != nil && user.Username != nil {
			log.AdminUsername = user.Username
		}
	}

	return log
}

// handleAuditLogsByEntity GET /api/audit-logs/entity/{entity}/{entityID} - todos os logs para uma entidade
func (s *Server) handleAuditLogsByEntity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/audit-logs/entity/")
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")

	if len(parts) < 2 {
		respondError(w, http.StatusBadRequest, "Entity e EntityID são obrigatórios")
		return
	}

	entity := parts[0]
	entityID := parts[1]

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	offset := 0
	if off := r.URL.Query().Get("offset"); off != "" {
		if parsed, err := strconv.Atoi(off); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	logs, err := s.auditStore.GetAuditLogsByEntity(entity, entityID, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao buscar logs")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data":      logs,
		"entity":    entity,
		"entity_id": entityID,
		"limit":     limit,
		"offset":    offset,
	})
}

// AuditLogResponse é a estrutura de resposta para logs de auditoria com formatação
type AuditLogResponse struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	Operation       string    `json:"operation"`
	Entity          string    `json:"entity"`
	EntityID        string    `json:"entity_id"`
	AdminID         *string   `json:"admin_id,omitempty"`
	AdminUsername   *string   `json:"admin_username,omitempty"`
	OldValue        *string   `json:"old_value,omitempty"`
	NewValue        *string   `json:"new_value,omitempty"`
	Status          string    `json:"status"`
	ErrorMessage    *string   `json:"error_message,omitempty"`
	IPAddress       *string   `json:"ip_address,omitempty"`
	UserAgent       *string   `json:"user_agent,omitempty"`
	RequestMethod   *string   `json:"request_method,omitempty"`
	RequestPath     *string   `json:"request_path,omitempty"`
	RequestID       *string   `json:"request_id,omitempty"`
	ResponseCode    *int      `json:"response_code,omitempty"`
	ExecutionTimeMs *int      `json:"execution_time_ms,omitempty"`
}

// handleAuditLogsExport GET /api/audit-logs/export - exporta logs em JSON
func (s *Server) handleAuditLogsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	query := r.URL.Query()

	var entity *string
	if e := query.Get("entity"); e != "" {
		entity = &e
	}

	var operation *string
	if o := query.Get("operation"); o != "" {
		operation = &o
	}

	var adminID *string
	if a := query.Get("admin_id"); a != "" {
		adminID = &a
	}

	var adminSearch *string
	if as := query.Get("admin_search"); as != "" {
		adminSearch = &as
	}

	var entitySearch *string
	if es := query.Get("entity_search"); es != "" {
		entitySearch = &es
	}

	var changedData *string
	if cd := query.Get("changed_data"); cd != "" {
		changedData = &cd
	}

	filter := store.AuditLogFilter{
		Entity:       entity,
		Operation:    operation,
		AdminID:      adminID,
		AdminSearch:  adminSearch,
		EntitySearch: entitySearch,
		ChangedData:  changedData,
		Limit:        10000,
		Offset:       0,
	}

	logs, err := s.auditStore.ListAuditLogs(filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao exportar logs")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=audit_logs.json")
	json.NewEncoder(w).Encode(logs)
}
