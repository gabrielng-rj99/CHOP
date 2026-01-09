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

	var resource *string
	if e := query.Get("resource"); e != "" {
		resource = &e
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

	var resourceID *string
	if ei := query.Get("resource_id"); ei != "" {
		resourceID = &ei
	}

	var resourceSearch *string
	if es := query.Get("resource_search"); es != "" {
		resourceSearch = &es
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

	var requestMethod *string
	if rm := query.Get("request_method"); rm != "" {
		requestMethod = &rm
	}

	var requestPath *string
	if rp := query.Get("request_path"); rp != "" {
		requestPath = &rp
	}

	var responseCode *int
	if rc := query.Get("response_code"); rc != "" {
		if parsed, err := strconv.Atoi(rc); err == nil {
			responseCode = &parsed
		}
	}

	var executionTimeMs *int
	if et := query.Get("execution_time_ms"); et != "" {
		if parsed, err := strconv.Atoi(et); err == nil {
			executionTimeMs = &parsed
		}
	}

	var errorMessage *string
	if em := query.Get("error_message"); em != "" {
		errorMessage = &em
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
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			if parsed > 1000 {
				limit = 1000
			} else {
				limit = parsed
			}
		}
	}

	offset := 0
	if off := query.Get("offset"); off != "" {
		if parsed, err := strconv.Atoi(off); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	filter := store.AuditLogFilter{
		Resource:        resource,
		Operation:       operation,
		AdminID:         adminID,
		AdminSearch:     adminSearch,
		ResourceID:      resourceID,
		ResourceSearch:  resourceSearch,
		ChangedData:     changedData,
		Status:          status,
		IPAddress:       ipAddress,
		RequestMethod:   requestMethod,
		RequestPath:     requestPath,
		ResponseCode:    responseCode,
		ExecutionTimeMs: executionTimeMs,
		ErrorMessage:    errorMessage,
		StartDate:       startDate,
		EndDate:         endDate,
		Limit:           limit,
		Offset:          offset,
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

// handleAuditLogsByResource GET /api/audit-logs/resource/{resource}/{resourceID} - todos os logs para um recurso
func (s *Server) handleAuditLogsByResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/audit-logs/resource/")
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")

	if len(parts) < 2 {
		respondError(w, http.StatusBadRequest, "Resource e ResourceID são obrigatórios")
		return
	}

	resource := parts[0]
	resourceID := parts[1]

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

	logs, err := s.auditStore.GetAuditLogsByResource(resource, resourceID, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Erro ao buscar logs")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data":        logs,
		"resource":    resource,
		"resource_id": resourceID,
		"limit":       limit,
		"offset":      offset,
	})
}

// AuditLogResponse é a estrutura de resposta para logs de auditoria com formatação
type AuditLogResponse struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	Operation       string    `json:"operation"`
	Resource        string    `json:"resource"`
	ResourceID      string    `json:"resource_id"`
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

	var resource *string
	if e := query.Get("resource"); e != "" {
		resource = &e
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

	var resourceSearch *string
	if es := query.Get("resource_search"); es != "" {
		resourceSearch = &es
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

	var requestMethod *string
	if rm := query.Get("request_method"); rm != "" {
		requestMethod = &rm
	}

	var requestPath *string
	if rp := query.Get("request_path"); rp != "" {
		requestPath = &rp
	}

	var responseCode *int
	if rc := query.Get("response_code"); rc != "" {
		if parsed, err := strconv.Atoi(rc); err == nil {
			responseCode = &parsed
		}
	}

	var executionTimeMs *int
	if et := query.Get("execution_time_ms"); et != "" {
		if parsed, err := strconv.Atoi(et); err == nil {
			executionTimeMs = &parsed
		}
	}

	var errorMessage *string
	if em := query.Get("error_message"); em != "" {
		errorMessage = &em
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

	filter := store.AuditLogFilter{
		Resource:        resource,
		Operation:       operation,
		AdminID:         adminID,
		AdminSearch:     adminSearch,
		ResourceSearch:  resourceSearch,
		ChangedData:     changedData,
		Status:          status,
		IPAddress:       ipAddress,
		RequestMethod:   requestMethod,
		RequestPath:     requestPath,
		ResponseCode:    responseCode,
		ExecutionTimeMs: executionTimeMs,
		ErrorMessage:    errorMessage,
		StartDate:       startDate,
		EndDate:         endDate,
		Limit:           10000,
		Offset:          0,
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
