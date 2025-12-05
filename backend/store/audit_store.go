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

package store

import (
	"Open-Generic-Hub/backend/domain"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AuditStore gerencia operações de auditoria
type AuditStore struct {
	db DBInterface
}

// NewAuditStore cria uma nova instância de AuditStore
func NewAuditStore(db DBInterface) *AuditStore {
	return &AuditStore{db: db}
}

// AuditLogRequest contém todos os dados necessários para registrar uma operação
type AuditLogRequest struct {
	Operation       string
	Entity          string
	EntityID        string
	AdminID         *string
	AdminUsername   *string
	OldValue        interface{}
	NewValue        interface{}
	Status          string
	ErrorMessage    *string
	IPAddress       *string
	UserAgent       *string
	RequestMethod   *string
	RequestPath     *string
	RequestID       *string
	ResponseCode    *int
	ExecutionTimeMs *int
}

// LogOperation registra uma operação com todos os detalhes
func (s *AuditStore) LogOperation(req AuditLogRequest) (string, error) {
	// Validar operação
	validOps := map[string]bool{
		"create": true,
		"read":   true,
		"update": true,
		"delete": true,
		"login":  true,
	}
	if !validOps[req.Operation] {
		return "", fmt.Errorf("operação inválida: %s", req.Operation)
	}

	// Validar entity
	validEntities := map[string]bool{
		"user":      true,
		"entity":    true,
		"agreement":  true,
		"subcategory":      true,
		"category":  true,
		"sub_entity": true,
		"audit_log": true,
		"auth":      true,
	}
	if !validEntities[req.Entity] {
		return "", fmt.Errorf("entidade inválida: %s", req.Entity)
	}

	// Validar status
	validStatuses := map[string]bool{
		"success": true,
		"error":   true,
		"failed":  true,
	}
	if !validStatuses[req.Status] {
		req.Status = "success"
	}

	id := uuid.New().String()

	var oldValueStr, newValueStr *string

	// Converter old_value para JSON string
	if req.OldValue != nil {
		if jsonData, err := json.Marshal(req.OldValue); err == nil {
			str := string(jsonData)
			oldValueStr = &str
		}
	}

	// Converter new_value para JSON string
	if req.NewValue != nil {
		if jsonData, err := json.Marshal(req.NewValue); err == nil {
			str := string(jsonData)
			newValueStr = &str
		}
	}

	sqlStatement := `
		INSERT INTO audit_logs (
			id, timestamp, operation, entity, entity_id, admin_id, admin_username,
			old_value, new_value, status, error_message, ip_address, user_agent,
			request_method, request_path, request_id, response_code, execution_time_ms
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
		)
	`

	_, err := s.db.Exec(
		sqlStatement,
		id,
		time.Now(),
		req.Operation,
		req.Entity,
		req.EntityID,
		req.AdminID,
		req.AdminUsername,
		oldValueStr,
		newValueStr,
		req.Status,
		req.ErrorMessage,
		req.IPAddress,
		req.UserAgent,
		req.RequestMethod,
		req.RequestPath,
		req.RequestID,
		req.ResponseCode,
		req.ExecutionTimeMs,
	)

	if err != nil {
		return "", err
	}

	return id, nil
}

// AuditLogFilter contém filtros para buscar logs
type AuditLogFilter struct {
	Entity       *string
	Operation    *string
	AdminID      *string
	AdminSearch  *string
	EntityID     *string
	EntitySearch *string
	ChangedData  *string
	Status       *string
	IPAddress    *string
	StartDate    *time.Time
	EndDate      *time.Time
	Limit        int
	Offset       int
}

// ListAuditLogs retorna logs de auditoria com filtros opcionais, ordenado por timestamp DESC
func (s *AuditStore) ListAuditLogs(filter AuditLogFilter) ([]domain.AuditLog, error) {
	if filter.Limit == 0 || filter.Limit > 1000 {
		filter.Limit = 100
	}

	query := `
		SELECT
			id, timestamp, operation, entity, entity_id, admin_id, admin_username,
			old_value, new_value, status, error_message, ip_address, user_agent,
			request_method, request_path, request_id, response_code, execution_time_ms
		FROM audit_logs
		WHERE 1=1
	`

	args := []interface{}{}
	argNum := 1

	if filter.Entity != nil && *filter.Entity != "" {
		query += fmt.Sprintf(" AND entity = $%d", argNum)
		args = append(args, *filter.Entity)
		argNum++
	}

	if filter.Operation != nil && *filter.Operation != "" {
		query += fmt.Sprintf(" AND operation = $%d", argNum)
		args = append(args, *filter.Operation)
		argNum++
	}

	if filter.AdminID != nil && *filter.AdminID != "" {
		query += fmt.Sprintf(" AND admin_id = $%d", argNum)
		args = append(args, *filter.AdminID)
		argNum++
	}

	if filter.AdminSearch != nil && *filter.AdminSearch != "" {
		query += fmt.Sprintf(" AND (admin_id = $%d OR admin_username ILIKE $%d)", argNum, argNum+1)
		args = append(args, *filter.AdminSearch, "%"+*filter.AdminSearch+"%")
		argNum += 2
	}

	if filter.EntitySearch != nil && *filter.EntitySearch != "" {
		query += fmt.Sprintf(" AND (entity_id = $%d OR old_value ILIKE $%d OR new_value ILIKE $%d)", argNum, argNum+1, argNum+2)
		args = append(args, *filter.EntitySearch, "%"+*filter.EntitySearch+"%", "%"+*filter.EntitySearch+"%")
		argNum += 3
	}

	if filter.ChangedData != nil && *filter.ChangedData != "" {
		query += fmt.Sprintf(" AND (old_value ILIKE $%d OR new_value ILIKE $%d)", argNum, argNum+1)
		args = append(args, "%"+*filter.ChangedData+"%", "%"+*filter.ChangedData+"%")
		argNum += 2
	}

	if filter.EntityID != nil && *filter.EntityID != "" {
		query += fmt.Sprintf(" AND entity_id = $%d", argNum)
		args = append(args, *filter.EntityID)
		argNum++
	}

	if filter.Status != nil && *filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, *filter.Status)
		argNum++
	}

	if filter.IPAddress != nil && *filter.IPAddress != "" {
		query += fmt.Sprintf(" AND ip_address = $%d", argNum)
		args = append(args, *filter.IPAddress)
		argNum++
	}

	if filter.StartDate != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argNum)
		args = append(args, *filter.StartDate)
		argNum++
	}

	if filter.EndDate != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argNum)
		args = append(args, *filter.EndDate)
		argNum++
	}

	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []domain.AuditLog
	for rows.Next() {
		var log domain.AuditLog
		var adminID, adminUsername, oldValue, newValue, errorMsg, ip, ua, method, path, reqID sql.NullString
		var responseCode, execTime sql.NullInt64

		err := rows.Scan(
			&log.ID,
			&log.Timestamp,
			&log.Operation,
			&log.Entity,
			&log.EntityID,
			&adminID,
			&adminUsername,
			&oldValue,
			&newValue,
			&log.Status,
			&errorMsg,
			&ip,
			&ua,
			&method,
			&path,
			&reqID,
			&responseCode,
			&execTime,
		)
		if err != nil {
			return nil, err
		}

		// Converter sql.NullString para *string
		if adminID.Valid {
			log.AdminID = &adminID.String
		}
		if adminUsername.Valid {
			log.AdminUsername = &adminUsername.String
		}
		if oldValue.Valid {
			log.OldValue = &oldValue.String
		}
		if newValue.Valid {
			log.NewValue = &newValue.String
		}
		if errorMsg.Valid {
			log.ErrorMessage = &errorMsg.String
		}
		if ip.Valid {
			log.IPAddress = &ip.String
		}
		if ua.Valid {
			log.UserAgent = &ua.String
		}
		if method.Valid {
			log.RequestMethod = &method.String
		}
		if path.Valid {
			log.RequestPath = &path.String
		}
		if reqID.Valid {
			log.RequestID = &reqID.String
		}
		if responseCode.Valid {
			code := int(responseCode.Int64)
			log.ResponseCode = &code
		}
		if execTime.Valid {
			time := int(execTime.Int64)
			log.ExecutionTimeMs = &time
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return logs, nil
}

// GetAuditLogByID retorna um log de auditoria específico
func (s *AuditStore) GetAuditLogByID(logID string) (*domain.AuditLog, error) {
	query := `
		SELECT
			id, timestamp, operation, entity, entity_id, admin_id, admin_username,
			old_value, new_value, status, error_message, ip_address, user_agent,
			request_method, request_path, request_id, response_code, execution_time_ms
		FROM audit_logs
		WHERE id = $1
	`

	var log domain.AuditLog
	var adminID, adminUsername, oldValue, newValue, errorMsg, ip, ua, method, path, reqID sql.NullString
	var responseCode, execTime sql.NullInt64

	err := s.db.QueryRow(query, logID).Scan(
		&log.ID,
		&log.Timestamp,
		&log.Operation,
		&log.Entity,
		&log.EntityID,
		&adminID,
		&adminUsername,
		&oldValue,
		&newValue,
		&log.Status,
		&errorMsg,
		&ip,
		&ua,
		&method,
		&path,
		&reqID,
		&responseCode,
		&execTime,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("log de auditoria não encontrado")
		}
		return nil, err
	}

	// Converter sql.NullString para *string
	if adminID.Valid {
		log.AdminID = &adminID.String
	}
	if adminUsername.Valid {
		log.AdminUsername = &adminUsername.String
	}
	if oldValue.Valid {
		log.OldValue = &oldValue.String
	}
	if newValue.Valid {
		log.NewValue = &newValue.String
	}
	if errorMsg.Valid {
		log.ErrorMessage = &errorMsg.String
	}
	if ip.Valid {
		log.IPAddress = &ip.String
	}
	if ua.Valid {
		log.UserAgent = &ua.String
	}
	if method.Valid {
		log.RequestMethod = &method.String
	}
	if path.Valid {
		log.RequestPath = &path.String
	}
	if reqID.Valid {
		log.RequestID = &reqID.String
	}
	if responseCode.Valid {
		code := int(responseCode.Int64)
		log.ResponseCode = &code
	}
	if execTime.Valid {
		time := int(execTime.Int64)
		log.ExecutionTimeMs = &time
	}

	return &log, nil
}

// GetAuditLogsByEntity retorna todos os logs para uma entidade específica
func (s *AuditStore) GetAuditLogsByEntity(entity, entityID string, limit, offset int) ([]domain.AuditLog, error) {
	if limit == 0 || limit > 1000 {
		limit = 100
	}

	filter := AuditLogFilter{
		Entity:   &entity,
		EntityID: &entityID,
		Limit:    limit,
		Offset:   offset,
	}

	return s.ListAuditLogs(filter)
}

// GetAuditLogsByAdmin retorna todos os logs de um admin específico
func (s *AuditStore) GetAuditLogsByAdmin(adminID string, limit, offset int) ([]domain.AuditLog, error) {
	if limit == 0 || limit > 1000 {
		limit = 100
	}

	filter := AuditLogFilter{
		AdminID: &adminID,
		Limit:   limit,
		Offset:  offset,
	}

	return s.ListAuditLogs(filter)
}

// CountAuditLogs retorna o número total de logs com os filtros aplicados
func (s *AuditStore) CountAuditLogs(filter AuditLogFilter) (int, error) {
	query := `SELECT COUNT(*) FROM audit_logs WHERE 1=1`
	args := []interface{}{}
	argNum := 1

	if filter.Entity != nil && *filter.Entity != "" {
		query += fmt.Sprintf(" AND entity = $%d", argNum)
		args = append(args, *filter.Entity)
		argNum++
	}

	if filter.Operation != nil && *filter.Operation != "" {
		query += fmt.Sprintf(" AND operation = $%d", argNum)
		args = append(args, *filter.Operation)
		argNum++
	}

	if filter.AdminID != nil && *filter.AdminID != "" {
		query += fmt.Sprintf(" AND admin_id = $%d", argNum)
		args = append(args, *filter.AdminID)
		argNum++
	}

	if filter.AdminSearch != nil && *filter.AdminSearch != "" {
		query += fmt.Sprintf(" AND (admin_id = $%d OR admin_username ILIKE $%d)", argNum, argNum+1)
		args = append(args, *filter.AdminSearch, "%"+*filter.AdminSearch+"%")
		argNum += 2
	}

	if filter.EntitySearch != nil && *filter.EntitySearch != "" {
		query += fmt.Sprintf(" AND (entity_id = $%d OR old_value ILIKE $%d OR new_value ILIKE $%d)", argNum, argNum+1, argNum+2)
		args = append(args, *filter.EntitySearch, "%"+*filter.EntitySearch+"%", "%"+*filter.EntitySearch+"%")
		argNum += 3
	}

	if filter.ChangedData != nil && *filter.ChangedData != "" {
		query += fmt.Sprintf(" AND (old_value ILIKE $%d OR new_value ILIKE $%d)", argNum, argNum+1)
		args = append(args, "%"+*filter.ChangedData+"%", "%"+*filter.ChangedData+"%")
		argNum += 2
	}

	if filter.EntityID != nil && *filter.EntityID != "" {
		query += fmt.Sprintf(" AND entity_id = $%d", argNum)
		args = append(args, *filter.EntityID)
		argNum++
	}

	if filter.Status != nil && *filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, *filter.Status)
		argNum++
	}

	if filter.IPAddress != nil && *filter.IPAddress != "" {
		query += fmt.Sprintf(" AND ip_address = $%d", argNum)
		args = append(args, *filter.IPAddress)
		argNum++
	}

	if filter.StartDate != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argNum)
		args = append(args, *filter.StartDate)
		argNum++
	}

	if filter.EndDate != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argNum)
		args = append(args, *filter.EndDate)
		argNum++
	}

	var count int
	err := s.db.QueryRow(query, args...).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// DeleteOldAuditLogs remove logs de auditoria mais antigos que o número de dias especificado
// Retorna o número de linhas deletadas
func (s *AuditStore) DeleteOldAuditLogs(daysOld int) (int64, error) {
	if daysOld < 1 {
		return 0, errors.New("daysOld deve ser maior que 0")
	}

	query := `DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '1 day' * $1`
	result, err := s.db.Exec(query, daysOld)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// GetAuditLogsWithCount retorna logs e o total de registros
func (s *AuditStore) GetAuditLogsWithCount(filter AuditLogFilter) ([]domain.AuditLog, int, error) {
	// Obter total primeiro
	total, err := s.CountAuditLogs(filter)
	if err != nil {
		return nil, 0, err
	}

	// Obter logs
	logs, err := s.ListAuditLogs(filter)
	if err != nil {
		return nil, total, err
	}

	return logs, total, nil
}
