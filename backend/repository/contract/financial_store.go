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

package contractstore

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/repository"

	"github.com/google/uuid"
)

// FinancialStore gerencia operações de financeiro no banco de dados
type FinancialStore struct {
	db repository.DBWithTx
}

// NewFinancialStore cria uma nova instância de FinancialStore
func NewFinancialStore(db repository.DBWithTx) *FinancialStore {
	return &FinancialStore{db: db}
}

// ============================================
// CONTRACT FINANCIAL CRUD
// ============================================

// CreateContractFinancial cria um novo modelo de financeiro para um contrato
func (s *FinancialStore) CreateContractFinancial(financial domain.ContractFinancial) (string, error) {
	// Validar tipo de financeiro
	if financial.FinancialType != "unico" && financial.FinancialType != "recorrente" && financial.FinancialType != "personalizado" {
		return "", errors.New("tipo de financeiro inválido: deve ser 'unico', 'recorrente' ou 'personalizado'")
	}

	// Para recorrente, validar recurrence_type
	if financial.FinancialType == "recorrente" {
		if financial.RecurrenceType == nil {
			return "", errors.New("tipo de recorrência é obrigatório para financeiro recorrentes")
		}
		rt := *financial.RecurrenceType
		if rt != "mensal" && rt != "trimestral" && rt != "semestral" && rt != "anual" {
			return "", errors.New("tipo de recorrência inválido")
		}
	}

	// Validar valores obrigatórios
	if financial.ClientValue == nil {
		return "", errors.New("client_value é obrigatório")
	}
	if financial.ReceivedValue == nil {
		return "", errors.New("received_value é obrigatório")
	}

	// Buscar datas do contrato
	var contractStartDate, contractEndDate *time.Time
	contractQuery := `SELECT start_date, end_date FROM contracts WHERE id = $1`
	err := s.db.QueryRow(contractQuery, financial.ContractID).Scan(&contractStartDate, &contractEndDate)
	if err != nil {
		return "", fmt.Errorf("erro ao buscar datas do contrato: %w", err)
	}

	// Gerar UUID
	id := uuid.New().String()

	query := `
		INSERT INTO contract_financial (
			id, contract_id, financial_type, recurrence_type, due_day,
			client_value, received_value, description, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
	`

	now := time.Now()
	_, err = s.db.Exec(query,
		id,
		financial.ContractID,
		financial.FinancialType,
		financial.RecurrenceType,
		financial.DueDay,
		financial.ClientValue,
		financial.ReceivedValue,
		financial.Description,
		true,
		now,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return "", errors.New("este contrato já possui um modelo de financeiro configurado")
		}
		return "", fmt.Errorf("erro ao criar financeiro: %w", err)
	}

	// Criar parcelas automaticamente para 'unico' e 'recorrente'
	if financial.FinancialType == "unico" || financial.FinancialType == "recorrente" {
		err = s.createAutomaticInstallments(id, financial, contractStartDate, contractEndDate)
		if err != nil {
			// Rollback: deletar o financeiro criado
			s.db.Exec(`DELETE FROM contract_financial WHERE id = $1`, id)
			return "", fmt.Errorf("erro ao criar parcelas automáticas: %w", err)
		}
	}

	return id, nil
}

// GetContractFinancialByID retorna um financeiro pelo ID
func (s *FinancialStore) GetContractFinancialByID(id string) (*domain.ContractFinancial, error) {
	query := `
		SELECT
			id, contract_id, financial_type, recurrence_type, due_day,
			client_value, received_value, description, is_active,
			created_at, updated_at
		FROM contract_financial
		WHERE id = $1
	`

	var financial domain.ContractFinancial
	err := s.db.QueryRow(query, id).Scan(
		&financial.ID,
		&financial.ContractID,
		&financial.FinancialType,
		&financial.RecurrenceType,
		&financial.DueDay,
		&financial.ClientValue,
		&financial.ReceivedValue,
		&financial.Description,
		&financial.IsActive,
		&financial.CreatedAt,
		&financial.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// Carregar parcelas se for personalizado
	if financial.FinancialType == "personalizado" {
		installments, err := s.GetInstallmentsByFinancialID(financial.ID)
		if err != nil {
			return nil, err
		}
		financial.Installments = installments
	}

	// Calcular totais
	s.calculateFinancialTotals(&financial)

	return &financial, nil
}

// GetContractFinancialByContractID retorna o financeiro de um contrato específico
func (s *FinancialStore) GetContractFinancialByContractID(contractID string) (*domain.ContractFinancial, error) {
	query := `
		SELECT
			id, contract_id, financial_type, recurrence_type, due_day,
			client_value, received_value, description, is_active,
			created_at, updated_at
		FROM contract_financial
		WHERE contract_id = $1
	`

	var financial domain.ContractFinancial
	err := s.db.QueryRow(query, contractID).Scan(
		&financial.ID,
		&financial.ContractID,
		&financial.FinancialType,
		&financial.RecurrenceType,
		&financial.DueDay,
		&financial.ClientValue,
		&financial.ReceivedValue,
		&financial.Description,
		&financial.IsActive,
		&financial.CreatedAt,
		&financial.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// Carregar parcelas se for personalizado
	if financial.FinancialType == "personalizado" {
		installments, err := s.GetInstallmentsByFinancialID(financial.ID)
		if err != nil {
			return nil, err
		}
		financial.Installments = installments
	}

	// Calcular totais
	s.calculateFinancialTotals(&financial)

	return &financial, nil
}

// UpdateContractFinancial atualiza um financeiro existente
func (s *FinancialStore) UpdateContractFinancial(financial domain.ContractFinancial) error {
	// Validar tipo de financeiro
	if financial.FinancialType != "unico" && financial.FinancialType != "recorrente" && financial.FinancialType != "personalizado" {
		return errors.New("tipo de financeiro inválido")
	}

	query := `
		UPDATE contract_financial SET
			financial_type = $1,
			recurrence_type = $2,
			due_day = $3,
			client_value = $4,
			received_value = $5,
			description = $6,
			is_active = $7,
			updated_at = $8
		WHERE id = $9
	`

	result, err := s.db.Exec(query,
		financial.FinancialType,
		financial.RecurrenceType,
		financial.DueDay,
		financial.ClientValue,
		financial.ReceivedValue,
		financial.Description,
		financial.IsActive,
		time.Now(),
		financial.ID,
	)

	if err != nil {
		return fmt.Errorf("erro ao atualizar financeiro: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("financeiro não encontrado")
	}

	return nil
}

// DeleteContractFinancial remove um financeiro (e suas parcelas em cascata)
func (s *FinancialStore) DeleteContractFinancial(id string) error {
	query := `DELETE FROM contract_financial WHERE id = $1`

	result, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("erro ao deletar financeiro: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("financeiro não encontrado")
	}

	return nil
}

// GetAllFinancials retorna todos os financeiro com informações resumidas
func (s *FinancialStore) GetAllFinancials() ([]domain.ContractFinancial, error) {
	query := `
		SELECT
			cp.id, cp.contract_id, cp.financial_type, cp.recurrence_type, cp.due_day,
			cp.client_value, cp.received_value, cp.description, cp.is_active,
			cp.created_at, cp.updated_at,
			COALESCE(c.model, '') AS contract_model,
			COALESCE(cl.name, '') AS client_name,
			cl.nickname AS client_nickname,
			COALESCE(cat.name, '') AS category_name,
			COALESCE(sub.name, '') AS subcategory_name,
			c.start_date AS contract_start,
			c.end_date AS contract_end
		FROM contract_financial cp
		JOIN contracts c ON c.id = cp.contract_id
		LEFT JOIN clients cl ON cl.id = c.client_id
		LEFT JOIN subcategories sub ON sub.id = c.subcategory_id
		LEFT JOIN categories cat ON cat.id = sub.category_id
		WHERE c.archived_at IS NULL
		ORDER BY cp.created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var financials []domain.ContractFinancial
	var personalizedIDs []string
	for rows.Next() {
		var f domain.ContractFinancial
		var clientNickname sql.NullString
		var contractStart, contractEnd sql.NullTime
		err := rows.Scan(
			&f.ID,
			&f.ContractID,
			&f.FinancialType,
			&f.RecurrenceType,
			&f.DueDay,
			&f.ClientValue,
			&f.ReceivedValue,
			&f.Description,
			&f.IsActive,
			&f.CreatedAt,
			&f.UpdatedAt,
			&f.ContractModel,
			&f.ClientName,
			&clientNickname,
			&f.CategoryName,
			&f.SubcategoryName,
			&contractStart,
			&contractEnd,
		)
		if err != nil {
			return nil, err
		}

		if clientNickname.Valid {
			f.ClientNickname = &clientNickname.String
		}
		if contractStart.Valid {
			f.ContractStart = &contractStart.Time
		}
		if contractEnd.Valid {
			f.ContractEnd = &contractEnd.Time
		}

		if f.FinancialType == "personalizado" {
			personalizedIDs = append(personalizedIDs, f.ID)
		} else {
			// Para único ou recorrente, usar os valores base
			f.TotalClientValue = f.ClientValue
			f.TotalReceivedValue = f.ReceivedValue
			f.TotalInstallments = 0
			f.PaidInstallments = 0
		}

		financials = append(financials, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Batch calculate totals for personalized financials (1 query instead of N)
	if len(personalizedIDs) > 0 {
		totalsMap, err := s.calculateFinancialTotalsBatch(personalizedIDs)
		if err != nil {
			return nil, err
		}
		for i := range financials {
			if financials[i].FinancialType == "personalizado" {
				if totals, ok := totalsMap[financials[i].ID]; ok {
					financials[i].TotalClientValue = &totals.totalClient
					financials[i].TotalReceivedValue = &totals.totalReceived
					financials[i].TotalInstallments = totals.total
					financials[i].PaidInstallments = totals.paid
				} else {
					zero := 0.0
					financials[i].TotalClientValue = &zero
					financials[i].TotalReceivedValue = &zero
					financials[i].TotalInstallments = 0
					financials[i].PaidInstallments = 0
				}
			}
		}
	}

	return financials, nil
}

// GetAllFinancialsPaged retorna financeiros com paginação real (server-side)
func (s *FinancialStore) GetAllFinancialsPaged(limit, offset int) ([]domain.ContractFinancial, error) {
	query := `
		SELECT
			cp.id, cp.contract_id, cp.financial_type, cp.recurrence_type, cp.due_day,
			cp.client_value, cp.received_value, cp.description, cp.is_active,
			cp.created_at, cp.updated_at,
			COALESCE(c.model, '') AS contract_model,
			COALESCE(cl.name, '') AS client_name,
			cl.nickname AS client_nickname,
			COALESCE(cat.name, '') AS category_name,
			COALESCE(sub.name, '') AS subcategory_name,
			c.start_date AS contract_start,
			c.end_date AS contract_end
		FROM contract_financial cp
		JOIN contracts c ON c.id = cp.contract_id
		LEFT JOIN clients cl ON cl.id = c.client_id
		LEFT JOIN subcategories sub ON sub.id = c.subcategory_id
		LEFT JOIN categories cat ON cat.id = sub.category_id
		WHERE c.archived_at IS NULL
		ORDER BY cp.created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := s.db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var financials []domain.ContractFinancial
	var personalizedIDs []string
	for rows.Next() {
		var f domain.ContractFinancial
		var clientNickname sql.NullString
		var contractStart, contractEnd sql.NullTime
		err := rows.Scan(
			&f.ID,
			&f.ContractID,
			&f.FinancialType,
			&f.RecurrenceType,
			&f.DueDay,
			&f.ClientValue,
			&f.ReceivedValue,
			&f.Description,
			&f.IsActive,
			&f.CreatedAt,
			&f.UpdatedAt,
			&f.ContractModel,
			&f.ClientName,
			&clientNickname,
			&f.CategoryName,
			&f.SubcategoryName,
			&contractStart,
			&contractEnd,
		)
		if err != nil {
			return nil, err
		}

		if clientNickname.Valid {
			f.ClientNickname = &clientNickname.String
		}
		if contractStart.Valid {
			f.ContractStart = &contractStart.Time
		}
		if contractEnd.Valid {
			f.ContractEnd = &contractEnd.Time
		}

		if f.FinancialType == "personalizado" {
			personalizedIDs = append(personalizedIDs, f.ID)
		} else {
			// For único or recorrente, use base values directly
			f.TotalClientValue = f.ClientValue
			f.TotalReceivedValue = f.ReceivedValue
			f.TotalInstallments = 0
			f.PaidInstallments = 0
		}

		financials = append(financials, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Batch calculate totals for personalized financials (1 query instead of N)
	if len(personalizedIDs) > 0 {
		totalsMap, err := s.calculateFinancialTotalsBatch(personalizedIDs)
		if err != nil {
			return nil, err
		}
		for i := range financials {
			if financials[i].FinancialType == "personalizado" {
				if totals, ok := totalsMap[financials[i].ID]; ok {
					financials[i].TotalClientValue = &totals.totalClient
					financials[i].TotalReceivedValue = &totals.totalReceived
					financials[i].TotalInstallments = totals.total
					financials[i].PaidInstallments = totals.paid
				} else {
					zero := 0.0
					financials[i].TotalClientValue = &zero
					financials[i].TotalReceivedValue = &zero
					financials[i].TotalInstallments = 0
					financials[i].PaidInstallments = 0
				}
			}
		}
	}

	return financials, nil
}

// CountFinancials retorna o total de financeiros (para paginação)
func (s *FinancialStore) CountFinancials() (int, error) {
	query := `
		SELECT COUNT(*)
		FROM contract_financial cp
		JOIN contracts c ON c.id = cp.contract_id
		WHERE c.archived_at IS NULL
	`

	var count int
	err := s.db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// financialTotals holds batch-computed totals for a personalized financial
type financialTotals struct {
	totalClient   float64
	totalReceived float64
	total         int
	paid          int
}

// calculateFinancialTotalsBatch computes installment totals for multiple financials in 1 query
func (s *FinancialStore) calculateFinancialTotalsBatch(ids []string) (map[string]financialTotals, error) {
	query := `
		SELECT
			contract_financial_id,
			COALESCE(SUM(client_value), 0),
			COALESCE(SUM(received_value), 0),
			COUNT(*),
			COUNT(CASE WHEN status = 'pago' THEN 1 END)
		FROM financial_installments
		WHERE contract_financial_id = ANY($1)
		GROUP BY contract_financial_id
	`

	rows, err := s.db.Query(query, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]financialTotals, len(ids))
	for rows.Next() {
		var cfID string
		var ft financialTotals
		if err := rows.Scan(&cfID, &ft.totalClient, &ft.totalReceived, &ft.total, &ft.paid); err != nil {
			return nil, err
		}
		result[cfID] = ft
	}

	return result, rows.Err()
}

// ============================================
// FINANCIAL INSTALLMENTS CRUD
// ============================================

// CreateInstallment cria uma nova parcela
func (s *FinancialStore) CreateInstallment(installment domain.FinancialInstallment) (string, error) {
	id := uuid.New().String()

	// Se não tiver label, gerar um padrão
	label := installment.InstallmentLabel
	if label == nil || *label == "" {
		defaultLabel := domain.GetDefaultInstallmentLabel(installment.InstallmentNumber)
		label = &defaultLabel
	}

	query := `
		INSERT INTO financial_installments (
			id, contract_financial_id, installment_number, installment_label,
			client_value, received_value, due_date, paid_at, status, notes,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
	`

	now := time.Now()
	_, err := s.db.Exec(query,
		id,
		installment.ContractFinancialID,
		installment.InstallmentNumber,
		label,
		installment.ClientValue,
		installment.ReceivedValue,
		installment.DueDate,
		installment.PaidAt,
		"pendente",
		installment.Notes,
		now,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return "", errors.New("já existe uma parcela com este número para este financeiro")
		}
		return "", fmt.Errorf("erro ao criar parcela: %w", err)
	}

	return id, nil
}

// CreateInstallmentsBatch cria várias parcelas de uma vez
func (s *FinancialStore) CreateInstallmentsBatch(financialID string, installments []domain.FinancialInstallment) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO financial_installments (
			id, contract_financial_id, installment_number, installment_label,
			client_value, received_value, due_date, status, notes,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
	`

	now := time.Now()
	for _, inst := range installments {
		id := uuid.New().String()

		label := inst.InstallmentLabel
		if label == nil || *label == "" {
			defaultLabel := domain.GetDefaultInstallmentLabel(inst.InstallmentNumber)
			label = &defaultLabel
		}

		_, err := tx.Exec(query,
			id,
			financialID,
			inst.InstallmentNumber,
			label,
			inst.ClientValue,
			inst.ReceivedValue,
			inst.DueDate,
			"pendente",
			inst.Notes,
			now,
		)

		if err != nil {
			return fmt.Errorf("erro ao criar parcela %d: %w", inst.InstallmentNumber, err)
		}
	}

	return tx.Commit()
}

// GetInstallmentsByFinancialID retorna todas as parcelas de um financeiro
func (s *FinancialStore) GetInstallmentsByFinancialID(financialID string) ([]domain.FinancialInstallment, error) {
	query := `
		SELECT
			id, contract_financial_id, installment_number, installment_label,
			client_value, received_value, due_date, paid_at, status, notes,
			created_at, updated_at
		FROM financial_installments
		WHERE contract_financial_id = $1
		ORDER BY installment_number ASC
	`

	rows, err := s.db.Query(query, financialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var installments []domain.FinancialInstallment
	for rows.Next() {
		var inst domain.FinancialInstallment
		err := rows.Scan(
			&inst.ID,
			&inst.ContractFinancialID,
			&inst.InstallmentNumber,
			&inst.InstallmentLabel,
			&inst.ClientValue,
			&inst.ReceivedValue,
			&inst.DueDate,
			&inst.PaidAt,
			&inst.Status,
			&inst.Notes,
			&inst.CreatedAt,
			&inst.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		installments = append(installments, inst)
	}

	return installments, nil
}

// UpdateInstallment atualiza uma parcela
func (s *FinancialStore) UpdateInstallment(installment domain.FinancialInstallment) error {
	query := `
		UPDATE financial_installments SET
			installment_label = $1,
			client_value = $2,
			received_value = $3,
			due_date = $4,
			notes = $5,
			updated_at = $6
		WHERE id = $7
	`

	result, err := s.db.Exec(query,
		installment.InstallmentLabel,
		installment.ClientValue,
		installment.ReceivedValue,
		installment.DueDate,
		installment.Notes,
		time.Now(),
		installment.ID,
	)

	if err != nil {
		return fmt.Errorf("erro ao atualizar parcela: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("parcela não encontrada")
	}

	return nil
}

// MarkInstallmentAsPaid marca uma parcela como paga
func (s *FinancialStore) MarkInstallmentAsPaid(id string) error {
	query := `
		UPDATE financial_installments SET
			status = 'pago',
			paid_at = $1,
			updated_at = $1
		WHERE id = $2
	`

	now := time.Now()
	result, err := s.db.Exec(query, now, id)
	if err != nil {
		return fmt.Errorf("erro ao marcar parcela como paga: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("parcela não encontrada")
	}

	return nil
}

// MarkInstallmentAsPending marca uma parcela como pendente (desfaz financeiro)
func (s *FinancialStore) MarkInstallmentAsPending(id string) error {
	query := `
		UPDATE financial_installments SET
			status = 'pendente',
			paid_at = NULL,
			updated_at = $1
		WHERE id = $2
	`

	result, err := s.db.Exec(query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("erro ao marcar parcela como pendente: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("parcela não encontrada")
	}

	return nil
}

// DeleteInstallment remove uma parcela
func (s *FinancialStore) DeleteInstallment(id string) error {
	query := `DELETE FROM financial_installments WHERE id = $1`

	result, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("erro ao deletar parcela: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("parcela não encontrada")
	}

	return nil
}

// DeleteAllInstallmentsByFinancialID remove todas as parcelas de um financeiro
func (s *FinancialStore) DeleteAllInstallmentsByFinancialID(financialID string) error {
	query := `DELETE FROM financial_installments WHERE contract_financial_id = $1`
	_, err := s.db.Exec(query, financialID)
	return err
}

// ============================================
// QUERIES PARA DASHBOARD
// ============================================

// GetFinancialSummary retorna resumo de financeiro para dashboard
func (s *FinancialStore) GetFinancialSummary() (*domain.FinancialSummary, error) {
	query := `
		SELECT
			COALESCE(SUM(pi.received_value), 0) AS total_to_receive,
			COALESCE(SUM(pi.client_value), 0) AS total_client_pays,
			COALESCE(SUM(CASE WHEN pi.status = 'pago' THEN pi.received_value ELSE 0 END), 0) AS already_received,
			COUNT(CASE WHEN pi.status = 'pendente' THEN 1 END) AS pending_count,
			COUNT(CASE WHEN pi.status = 'pago' THEN 1 END) AS paid_count,
			COUNT(CASE WHEN pi.status = 'atrasado' THEN 1 END) AS overdue_count
		FROM financial_installments pi
		JOIN contract_financial cp ON cp.id = pi.contract_financial_id
		JOIN contracts c ON c.id = cp.contract_id
		WHERE c.archived_at IS NULL
	`

	var summary domain.FinancialSummary
	err := s.db.QueryRow(query).Scan(
		&summary.TotalToReceive,
		&summary.TotalClientPays,
		&summary.AlreadyReceived,
		&summary.PendingCount,
		&summary.PaidCount,
		&summary.OverdueCount,
	)

	if err != nil {
		return nil, err
	}

	return &summary, nil
}

// GetMonthlySummary retorna resumo de financeiro de um mês específico
func (s *FinancialStore) GetMonthlySummary(year int, month int) (*domain.FinancialSummary, error) {
	periodStart := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)

	query := `
		SELECT
			COALESCE(SUM(pi.received_value), 0) AS total_to_receive,
			COALESCE(SUM(pi.client_value), 0) AS total_client_pays,
			COALESCE(SUM(CASE WHEN pi.status = 'pago' THEN pi.received_value ELSE 0 END), 0) AS already_received,
			COUNT(CASE WHEN pi.status = 'pendente' THEN 1 END) AS pending_count,
			COUNT(CASE WHEN pi.status = 'pago' THEN 1 END) AS paid_count,
			COUNT(CASE WHEN pi.status = 'atrasado' THEN 1 END) AS overdue_count
		FROM financial_installments pi
		JOIN contract_financial cp ON cp.id = pi.contract_financial_id
		JOIN contracts c ON c.id = cp.contract_id
		WHERE c.archived_at IS NULL
		AND pi.due_date >= $1
		AND pi.due_date < $2
	`

	var summary domain.FinancialSummary
	err := s.db.QueryRow(query, periodStart, periodEnd).Scan(
		&summary.TotalToReceive,
		&summary.TotalClientPays,
		&summary.AlreadyReceived,
		&summary.PendingCount,
		&summary.PaidCount,
		&summary.OverdueCount,
	)

	if err != nil {
		return nil, err
	}

	return &summary, nil
}

// GetUpcomingFinancials retorna parcelas pendentes com vencimento próximo
func (s *FinancialStore) GetUpcomingFinancials(daysAhead int) ([]domain.UpcomingFinancial, error) {
	query := `
		SELECT
			pi.id,
			cp.id AS contract_financial_id,
			c.id AS contract_id,
			c.client_id,
			cl.name AS client_name,
			c.model AS contract_model,
			pi.installment_label,
			pi.client_value,
			pi.received_value,
			pi.due_date,
			pi.status
		FROM financial_installments pi
		JOIN contract_financial cp ON cp.id = pi.contract_financial_id
		JOIN contracts c ON c.id = cp.contract_id
		JOIN clients cl ON cl.id = c.client_id
		WHERE pi.status = 'pendente'
		AND pi.due_date IS NOT NULL
		AND pi.due_date <= CURRENT_DATE + INTERVAL '1 day' * $1
		AND c.archived_at IS NULL
		ORDER BY pi.due_date ASC
		LIMIT 50
	`

	rows, err := s.db.Query(query, daysAhead)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var financial []domain.UpcomingFinancial
	for rows.Next() {
		var p domain.UpcomingFinancial
		err := rows.Scan(
			&p.InstallmentID,
			&p.ContractFinancialID,
			&p.ContractID,
			&p.ClientID,
			&p.ClientName,
			&p.ContractModel,
			&p.InstallmentLabel,
			&p.ClientValue,
			&p.ReceivedValue,
			&p.DueDate,
			&p.Status,
		)
		if err != nil {
			return nil, err
		}
		financial = append(financial, p)
	}

	return financial, nil
}

// GetOverdueFinancials retorna parcelas em atraso
func (s *FinancialStore) GetOverdueFinancials() ([]domain.UpcomingFinancial, error) {
	query := `
		SELECT
			pi.id,
			cp.id AS contract_financial_id,
			c.id AS contract_id,
			c.client_id,
			cl.name AS client_name,
			c.model AS contract_model,
			pi.installment_label,
			pi.client_value,
			pi.received_value,
			pi.due_date,
			pi.status
		FROM financial_installments pi
		JOIN contract_financial cp ON cp.id = pi.contract_financial_id
		JOIN contracts c ON c.id = cp.contract_id
		JOIN clients cl ON cl.id = c.client_id
		WHERE pi.status IN ('pendente', 'atrasado')
		AND pi.due_date IS NOT NULL
		AND pi.due_date < CURRENT_DATE
		AND c.archived_at IS NULL
		ORDER BY pi.due_date ASC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var financial []domain.UpcomingFinancial
	for rows.Next() {
		var p domain.UpcomingFinancial
		err := rows.Scan(
			&p.InstallmentID,
			&p.ContractFinancialID,
			&p.ContractID,
			&p.ClientID,
			&p.ClientName,
			&p.ContractModel,
			&p.InstallmentLabel,
			&p.ClientValue,
			&p.ReceivedValue,
			&p.DueDate,
			&p.Status,
		)
		if err != nil {
			return nil, err
		}
		p.Status = "atrasado" // Marcar como atrasado na resposta
		financial = append(financial, p)
	}

	return financial, nil
}

// GetFinancialDetailedSummary retorna resumo detalhado de financeiro com dados por período
func (s *FinancialStore) GetFinancialDetailedSummary() (*domain.DetailedFinancialSummary, error) {
	summary := &domain.DetailedFinancialSummary{
		GeneratedAt: time.Now().Format(time.RFC3339),
		CurrentDate: time.Now().Format("2006-01-02"),
	}

	// Query 1: Totais gerais (1 query, unchanged)
	totalQuery := `
		SELECT
			COALESCE(SUM(pi.received_value), 0) AS total_to_receive,
			COALESCE(SUM(pi.client_value), 0) AS total_client_pays,
			COALESCE(SUM(CASE WHEN pi.status = 'pago' THEN pi.received_value ELSE 0 END), 0) AS total_received,
			COALESCE(SUM(CASE WHEN pi.status IN ('pendente', 'atrasado') THEN pi.received_value ELSE 0 END), 0) AS total_pending,
			COALESCE(SUM(CASE WHEN pi.status = 'atrasado' THEN pi.received_value ELSE 0 END), 0) AS total_overdue,
			COUNT(CASE WHEN pi.status = 'atrasado' THEN 1 END) AS total_overdue_count
		FROM financial_installments pi
		JOIN contract_financial cp ON cp.id = pi.contract_financial_id
		JOIN contracts c ON c.id = cp.contract_id
		WHERE c.archived_at IS NULL
	`

	err := s.db.QueryRow(totalQuery).Scan(
		&summary.TotalToReceive,
		&summary.TotalClientPays,
		&summary.TotalReceived,
		&summary.TotalPending,
		&summary.TotalOverdue,
		&summary.TotalOverdueCount,
	)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar totais gerais: %w", err)
	}

	// Compute the full date range: -3 to +3 months from now
	now := time.Now()
	rangeStart := time.Date(now.Year(), now.Month()-3, 1, 0, 0, 0, 0, time.UTC)
	rangeEnd := time.Date(now.Year(), now.Month()+4, 1, 0, 0, 0, 0, time.UTC) // exclusive upper bound

	// Build all period summaries in batch (replaces 10 individual getPeriodSummary calls)
	allPeriods, err := s.getPeriodSummariesBatch(rangeStart, rangeEnd)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar resumos por período: %w", err)
	}

	// Map periods to their keys for quick lookup
	periodMap := make(map[string]*domain.PeriodSummary, len(allPeriods))
	for i := range allPeriods {
		periodMap[allPeriods[i].Period] = &allPeriods[i]
	}

	// Assign last/current/next month
	lastMonthKey := now.AddDate(0, -1, 0).Format("2006-01")
	currentMonthKey := now.Format("2006-01")
	nextMonthKey := now.AddDate(0, 1, 0).Format("2006-01")

	summary.LastMonth = periodMap[lastMonthKey]
	summary.CurrentMonth = periodMap[currentMonthKey]
	summary.NextMonth = periodMap[nextMonthKey]

	// Ensure non-nil period summaries with correct labels
	if summary.LastMonth == nil {
		lm := now.AddDate(0, -1, 0)
		summary.LastMonth = s.emptyPeriodSummary(lm.Year(), int(lm.Month()))
	}
	if summary.CurrentMonth == nil {
		summary.CurrentMonth = s.emptyPeriodSummary(now.Year(), int(now.Month()))
	}
	if summary.NextMonth == nil {
		nm := now.AddDate(0, 1, 0)
		summary.NextMonth = s.emptyPeriodSummary(nm.Year(), int(nm.Month()))
	}

	// Build monthly breakdown from -3 to +3
	summary.MonthlyBreakdown = make([]domain.PeriodSummary, 0, 7)
	for i := -3; i <= 3; i++ {
		m := now.AddDate(0, i, 0)
		key := m.Format("2006-01")
		if ps, ok := periodMap[key]; ok {
			summary.MonthlyBreakdown = append(summary.MonthlyBreakdown, *ps)
		} else {
			summary.MonthlyBreakdown = append(summary.MonthlyBreakdown, *s.emptyPeriodSummary(m.Year(), int(m.Month())))
		}
	}

	return summary, nil
}

// emptyPeriodSummary creates a zero-valued PeriodSummary with correct labels
func (s *FinancialStore) emptyPeriodSummary(year int, month int) *domain.PeriodSummary {
	monthNames := []string{"", "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
		"Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"}
	return &domain.PeriodSummary{
		Period:      fmt.Sprintf("%04d-%02d", year, month),
		PeriodLabel: fmt.Sprintf("%s %d", monthNames[month], year),
	}
}

// recurrentFinancial holds data for a single recurrent financial record (loaded once, reused for all periods)
type recurrentFinancial struct {
	cfID              string
	receivedValue     float64
	clientValue       float64
	recurrenceType    string
	dueDay            int
	contractStartDate time.Time
	contractEndDate   time.Time
	hasEndDate        bool
}

// getPeriodSummariesBatch computes PeriodSummary for every month in [rangeStart, rangeEnd).
// It replaces the old getPeriodSummary() which was called 10 times (each with its own N+1).
//
// Total queries: 3 (installment aggregates + recurrent list + batch installment status lookup)
// Previously: 10 × (1 aggregate + 1 recurrent load + ~1500 individual checks) ≈ 15,020 queries
func (s *FinancialStore) getPeriodSummariesBatch(rangeStart, rangeEnd time.Time) ([]domain.PeriodSummary, error) {
	monthNames := []string{"", "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
		"Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"}

	// ------------------------------------------------------------------
	// Query 2: Installment-based aggregates grouped by month (1 query)
	// Uses idx_fi_duedate_cfid_covering for Index-Only Scan
	// ------------------------------------------------------------------
	installmentQuery := `
		SELECT
			TO_CHAR(DATE_TRUNC('month', pi.due_date), 'YYYY-MM') AS period,
			COALESCE(SUM(pi.received_value), 0) AS total_to_receive,
			COALESCE(SUM(pi.client_value), 0) AS total_client_pays,
			COALESCE(SUM(CASE WHEN pi.status = 'pago' THEN pi.received_value ELSE 0 END), 0) AS already_received,
			COALESCE(SUM(CASE WHEN pi.status = 'pendente' THEN pi.received_value ELSE 0 END), 0) AS pending_amount,
			COUNT(CASE WHEN pi.status = 'pendente' THEN 1 END) AS pending_count,
			COUNT(CASE WHEN pi.status = 'pago' THEN 1 END) AS paid_count,
			COUNT(CASE WHEN pi.status = 'atrasado' THEN 1 END) AS overdue_count,
			COALESCE(SUM(CASE WHEN pi.status = 'atrasado' THEN pi.received_value ELSE 0 END), 0) AS overdue_amount
		FROM financial_installments pi
		JOIN contract_financial cp ON cp.id = pi.contract_financial_id
		JOIN contracts c ON c.id = cp.contract_id
		WHERE c.archived_at IS NULL
		AND pi.due_date >= $1
		AND pi.due_date < $2
		GROUP BY DATE_TRUNC('month', pi.due_date)
		ORDER BY DATE_TRUNC('month', pi.due_date)
	`

	rows, err := s.db.Query(installmentQuery, rangeStart, rangeEnd)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar aggregates de installments por mês: %w", err)
	}
	defer rows.Close()

	// Build a map of period -> PeriodSummary from installment data
	periodMap := make(map[string]*domain.PeriodSummary)
	for rows.Next() {
		var ps domain.PeriodSummary
		err := rows.Scan(
			&ps.Period,
			&ps.TotalToReceive,
			&ps.TotalClientPays,
			&ps.AlreadyReceived,
			&ps.PendingAmount,
			&ps.PendingCount,
			&ps.PaidCount,
			&ps.OverdueCount,
			&ps.OverdueAmount,
		)
		if err != nil {
			return nil, fmt.Errorf("erro ao escanear aggregate mensal: %w", err)
		}
		periodMap[ps.Period] = &ps
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// ------------------------------------------------------------------
	// Query 3: Load ALL active recurrent financials (1 query, loaded once)
	// Previously this was loaded 10 separate times inside getPeriodSummary
	// ------------------------------------------------------------------
	recurrentQuery := `
		SELECT
			cf.id,
			cf.received_value,
			cf.client_value,
			cf.recurrence_type,
			cf.due_day,
			c.start_date,
			c.end_date
		FROM contract_financial cf
		JOIN contracts c ON c.id = cf.contract_id
		WHERE c.archived_at IS NULL
		AND cf.financial_type = 'recorrente'
		AND cf.is_active = true
		AND cf.received_value IS NOT NULL
	`

	recRows, err := s.db.Query(recurrentQuery)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar receitas recorrentes: %w", err)
	}
	defer recRows.Close()

	var recurrents []recurrentFinancial
	recurrentIDs := make([]string, 0)
	for recRows.Next() {
		var rf recurrentFinancial
		var startDateStr, endDateStr sql.NullString

		err := recRows.Scan(&rf.cfID, &rf.receivedValue, &rf.clientValue, &rf.recurrenceType, &rf.dueDay, &startDateStr, &endDateStr)
		if err != nil {
			continue
		}

		if startDateStr.Valid {
			rf.contractStartDate, _ = time.Parse("2006-01-02", startDateStr.String)
		}
		if endDateStr.Valid {
			rf.contractEndDate, _ = time.Parse("2006-01-02", endDateStr.String)
			rf.hasEndDate = true
		}

		recurrents = append(recurrents, rf)
		recurrentIDs = append(recurrentIDs, rf.cfID)
	}
	if err := recRows.Err(); err != nil {
		return nil, err
	}

	// ------------------------------------------------------------------
	// Query 4: Batch lookup of installment statuses for ALL recurrents
	//          across the ENTIRE date range (1 query replaces ~15,000)
	// Uses idx_fi_cfid_duedate_covering for Index-Only Scan
	// ------------------------------------------------------------------
	// Key: "cfID|YYYY-MM" -> status string
	installmentStatusMap := make(map[string]string)

	if len(recurrentIDs) > 0 {
		batchQuery := `
			SELECT
				contract_financial_id,
				TO_CHAR(DATE_TRUNC('month', due_date), 'YYYY-MM') AS period,
				status
			FROM financial_installments
			WHERE contract_financial_id = ANY($1)
			AND due_date >= $2
			AND due_date < $3
		`

		statusRows, err := s.db.Query(batchQuery, recurrentIDs, rangeStart, rangeEnd)
		if err != nil {
			return nil, fmt.Errorf("erro ao buscar status de installments em batch: %w", err)
		}
		defer statusRows.Close()

		for statusRows.Next() {
			var cfID, period, status string
			if err := statusRows.Scan(&cfID, &period, &status); err != nil {
				continue
			}
			// Store the first status found per cfID+period (matches old LIMIT 1 behavior)
			key := cfID + "|" + period
			if _, exists := installmentStatusMap[key]; !exists {
				installmentStatusMap[key] = status
			}
		}
		if err := statusRows.Err(); err != nil {
			return nil, err
		}
	}

	// ------------------------------------------------------------------
	// Process: For each month in range, apply recurrent financials
	// All in memory, no more database calls
	// ------------------------------------------------------------------
	now := time.Now()
	current := rangeStart
	for current.Before(rangeEnd) {
		year := current.Year()
		month := int(current.Month())
		periodKey := fmt.Sprintf("%04d-%02d", year, month)

		// Ensure we have a PeriodSummary entry for this month
		ps, exists := periodMap[periodKey]
		if !exists {
			ps = &domain.PeriodSummary{}
			periodMap[periodKey] = ps
		}

		targetDate := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)

		// Apply each recurrent financial to this month
		for _, rf := range recurrents {
			// Check contract validity window
			if !rf.contractStartDate.IsZero() && targetDate.Before(time.Date(rf.contractStartDate.Year(), rf.contractStartDate.Month(), 1, 0, 0, 0, 0, time.UTC)) {
				continue
			}
			if rf.hasEndDate && !rf.contractEndDate.IsZero() {
				contractEndMonth := time.Date(rf.contractEndDate.Year(), rf.contractEndDate.Month(), 1, 0, 0, 0, 0, time.UTC)
				if targetDate.After(contractEndMonth) {
					continue
				}
			}

			// Check recurrence applies to this month
			shouldInclude := false
			switch rf.recurrenceType {
			case "mensal":
				shouldInclude = true
			case "trimestral":
				if !rf.contractStartDate.IsZero() {
					startMonth := int(rf.contractStartDate.Month())
					monthsSinceStart := (year-rf.contractStartDate.Year())*12 + (month - startMonth)
					shouldInclude = monthsSinceStart >= 0 && monthsSinceStart%3 == 0
				} else {
					shouldInclude = month == 1 || month == 4 || month == 7 || month == 10
				}
			case "semestral":
				if !rf.contractStartDate.IsZero() {
					startMonth := int(rf.contractStartDate.Month())
					monthsSinceStart := (year-rf.contractStartDate.Year())*12 + (month - startMonth)
					shouldInclude = monthsSinceStart >= 0 && monthsSinceStart%6 == 0
				} else {
					shouldInclude = month == 1 || month == 7
				}
			case "anual":
				if !rf.contractStartDate.IsZero() {
					startMonth := int(rf.contractStartDate.Month())
					startYear := rf.contractStartDate.Year()
					shouldInclude = year >= startYear && month == startMonth && (year-startYear) >= 0
				} else {
					shouldInclude = month == 1
				}
			}

			if !shouldInclude {
				continue
			}

			// Compute due date for this recurrent in this month
			dueDate := time.Date(year, time.Month(month), rf.dueDay, 0, 0, 0, 0, time.UTC)
			if rf.dueDay > 28 {
				lastDay := time.Date(year, time.Month(month+1), 0, 0, 0, 0, 0, time.UTC).Day()
				if rf.dueDay > lastDay {
					dueDate = time.Date(year, time.Month(month), lastDay, 0, 0, 0, 0, time.UTC)
				}
			}

			// Lookup installment status from the batch map (O(1) instead of 1 SQL query)
			lookupKey := rf.cfID + "|" + periodKey
			if installmentStatus, found := installmentStatusMap[lookupKey]; found {
				switch installmentStatus {
				case "pago":
					ps.AlreadyReceived += rf.receivedValue
					ps.PaidCount++
				case "pendente":
					ps.PendingAmount += rf.receivedValue
					ps.PendingCount++
				case "atrasado":
					ps.OverdueAmount += rf.receivedValue
					ps.OverdueCount++
				}
			} else {
				// No installment exists — classify by due date
				if dueDate.Before(now) {
					ps.OverdueAmount += rf.receivedValue
					ps.OverdueCount++
				} else {
					ps.PendingAmount += rf.receivedValue
					ps.PendingCount++
				}
			}

			ps.TotalToReceive += rf.receivedValue
			ps.TotalClientPays += rf.clientValue
		}

		// Set period label
		ps.Period = periodKey
		ps.PeriodLabel = fmt.Sprintf("%s %d", monthNames[month], year)

		// Advance to next month
		current = current.AddDate(0, 1, 0)
	}

	// Collect all periods in order
	result := make([]domain.PeriodSummary, 0, 7)
	current = rangeStart
	for current.Before(rangeEnd) {
		key := current.Format("2006-01")
		if ps, ok := periodMap[key]; ok {
			result = append(result, *ps)
		}
		current = current.AddDate(0, 1, 0)
	}

	return result, nil
}

// getPeriodSummary retorna o resumo de um período específico (mês/ano).
// Kept for backward compatibility but now delegates to getPeriodSummariesBatch
// with a single-month range.
func (s *FinancialStore) getPeriodSummary(year int, month int) (*domain.PeriodSummary, error) {
	rangeStart := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	rangeEnd := rangeStart.AddDate(0, 1, 0)

	periods, err := s.getPeriodSummariesBatch(rangeStart, rangeEnd)
	if err != nil {
		return nil, err
	}

	if len(periods) > 0 {
		return &periods[0], nil
	}

	return s.emptyPeriodSummary(year, month), nil
}

// UpdateOverdueStatus atualiza o status de parcelas vencidas para 'atrasado'
func (s *FinancialStore) UpdateOverdueStatus() (int64, error) {
	query := `
		UPDATE financial_installments SET
			status = 'atrasado',
			updated_at = CURRENT_TIMESTAMP
		WHERE status = 'pendente'
		AND due_date IS NOT NULL
		AND due_date < CURRENT_DATE
	`

	result, err := s.db.Exec(query)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// ============================================
// HELPERS
// ============================================

// calculateFinancialTotals calcula os totais de um financeiro
func (s *FinancialStore) calculateFinancialTotals(financial *domain.ContractFinancial) {
	if financial.FinancialType == "personalizado" {
		// Para personalizado, usar query para somar parcelas
		query := `
			SELECT
				COALESCE(SUM(client_value), 0),
				COALESCE(SUM(received_value), 0),
				COUNT(*),
				COUNT(CASE WHEN status = 'pago' THEN 1 END)
			FROM financial_installments
			WHERE contract_financial_id = $1
		`

		var totalClient, totalReceived float64
		var total, paid int

		err := s.db.QueryRow(query, financial.ID).Scan(
			&totalClient,
			&totalReceived,
			&total,
			&paid,
		)

		if err == nil {
			financial.TotalClientValue = &totalClient
			financial.TotalReceivedValue = &totalReceived
			financial.TotalInstallments = total
			financial.PaidInstallments = paid
		}
	} else {
		// Para único ou recorrente, usar os valores base
		financial.TotalClientValue = financial.ClientValue
		financial.TotalReceivedValue = financial.ReceivedValue
		financial.TotalInstallments = 0
		financial.PaidInstallments = 0
	}
}

// isUniqueViolation verifica se o erro é de violação de constraint unique
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() != "" &&
		(contains(err.Error(), "duplicate key") ||
			contains(err.Error(), "unique constraint") ||
			contains(err.Error(), "UNIQUE constraint"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

// createAutomaticInstallments cria parcelas automaticamente para financeiro 'unico' e 'recorrente'
func (s *FinancialStore) createAutomaticInstallments(financialID string, financial domain.ContractFinancial, startDate, endDate *time.Time) error {
	if startDate == nil {
		return errors.New("contrato deve ter data de início para criar financeiro automático")
	}

	var installments []domain.FinancialInstallment

	if financial.FinancialType == "unico" {
		// Para único, criar uma parcela com due_date = start_date
		installment := domain.FinancialInstallment{
			ContractFinancialID: financialID,
			InstallmentNumber:   1,
			ClientValue:         *financial.ClientValue,
			ReceivedValue:       *financial.ReceivedValue,
			DueDate:             startDate,
			Status:              "pendente",
		}
		installments = append(installments, installment)
	} else if financial.FinancialType == "recorrente" {
		// Para recorrente, criar parcelas baseadas na recorrência
		if financial.RecurrenceType == nil || financial.DueDay == nil {
			return errors.New("recorrência e dia de vencimento são obrigatórios para financeiro recorrente")
		}

		recurrenceType := *financial.RecurrenceType
		dueDay := *financial.DueDay

		// Calcular parcelas para os próximos 12 meses (ou até end_date se definido)
		currentDate := *startDate
		installmentNumber := 1
		maxInstallments := 12 // Limitar a 12 parcelas por padrão

		for i := 0; i < maxInstallments; i++ {
			// Calcular due_date baseado na recorrência
			var dueDate time.Time
			switch recurrenceType {
			case "mensal":
				dueDate = time.Date(currentDate.Year(), time.Month(int(currentDate.Month())+i), dueDay, 0, 0, 0, 0, time.UTC)
			case "trimestral":
				dueDate = time.Date(currentDate.Year(), time.Month(int(currentDate.Month())+(i*3)), dueDay, 0, 0, 0, 0, time.UTC)
			case "semestral":
				dueDate = time.Date(currentDate.Year(), time.Month(int(currentDate.Month())+(i*6)), dueDay, 0, 0, 0, 0, time.UTC)
			case "anual":
				dueDate = time.Date(currentDate.Year()+i, currentDate.Month(), dueDay, 0, 0, 0, 0, time.UTC)
			default:
				return errors.New("tipo de recorrência inválido")
			}

			// Ajustar para o último dia do mês se dueDay > dias do mês
			if dueDay > 28 {
				lastDay := time.Date(dueDate.Year(), time.Month(int(dueDate.Month())+1), 0, 0, 0, 0, 0, time.UTC).Day()
				if dueDay > lastDay {
					dueDate = time.Date(dueDate.Year(), dueDate.Month(), lastDay, 0, 0, 0, 0, time.UTC)
				}
			}

			// Parar se passou da end_date
			if endDate != nil && dueDate.After(*endDate) {
				break
			}

			installment := domain.FinancialInstallment{
				ContractFinancialID: financialID,
				InstallmentNumber:   installmentNumber,
				ClientValue:         *financial.ClientValue,
				ReceivedValue:       *financial.ReceivedValue,
				DueDate:             &dueDate,
				Status:              "pendente",
			}
			installments = append(installments, installment)
			installmentNumber++
		}
	}

	// Criar as parcelas em lote
	if len(installments) > 0 {
		return s.CreateInstallmentsBatch(financialID, installments)
	}

	return nil
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
