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
			cp.created_at, cp.updated_at
		FROM contract_financial cp
		JOIN contracts c ON c.id = cp.contract_id
		WHERE c.archived_at IS NULL
		ORDER BY cp.created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var financials []domain.ContractFinancial
	for rows.Next() {
		var f domain.ContractFinancial
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
		)
		if err != nil {
			return nil, err
		}

		// Calcular totais para cada financeiro
		s.calculateFinancialTotals(&f)
		financials = append(financials, f)
	}

	return financials, nil
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
		AND EXTRACT(YEAR FROM pi.due_date) = $1
		AND EXTRACT(MONTH FROM pi.due_date) = $2
	`

	var summary domain.FinancialSummary
	err := s.db.QueryRow(query, year, month).Scan(
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

	// Query para totais gerais
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

	// Buscar dados do mês passado
	lastMonth := time.Now().AddDate(0, -1, 0)
	summary.LastMonth, _ = s.getPeriodSummary(lastMonth.Year(), int(lastMonth.Month()))

	// Buscar dados do mês atual
	currentMonth := time.Now()
	summary.CurrentMonth, _ = s.getPeriodSummary(currentMonth.Year(), int(currentMonth.Month()))

	// Buscar dados do próximo mês
	nextMonth := time.Now().AddDate(0, 1, 0)
	summary.NextMonth, _ = s.getPeriodSummary(nextMonth.Year(), int(nextMonth.Month()))

	// Buscar breakdown mensal (últimos 3 meses + próximos 3 meses)
	summary.MonthlyBreakdown = make([]domain.PeriodSummary, 0)
	for i := -3; i <= 3; i++ {
		month := time.Now().AddDate(0, i, 0)
		periodSummary, err := s.getPeriodSummary(month.Year(), int(month.Month()))
		if err == nil && periodSummary != nil {
			summary.MonthlyBreakdown = append(summary.MonthlyBreakdown, *periodSummary)
		}
	}

	return summary, nil
}

// getPeriodSummary retorna o resumo de um período específico (mês/ano)
func (s *FinancialStore) getPeriodSummary(year int, month int) (*domain.PeriodSummary, error) {
	// Query para parcelas (financeiros personalizados e únicos)
	query := `
		SELECT
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
		AND EXTRACT(YEAR FROM pi.due_date) = $1
		AND EXTRACT(MONTH FROM pi.due_date) = $2
	`

	var ps domain.PeriodSummary
	err := s.db.QueryRow(query, year, month).Scan(
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
		return nil, err
	}

	// Adicionar receitas recorrentes para este período
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

	rows, err := s.db.Query(recurrentQuery)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar receitas recorrentes: %w", err)
	}
	defer rows.Close()

	targetDate := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)

	for rows.Next() {
		var cfID string
		var receivedValue, clientValue float64
		var recurrenceType string
		var dueDay int
		var startDateStr, endDateStr sql.NullString

		err := rows.Scan(&cfID, &receivedValue, &clientValue, &recurrenceType, &dueDay, &startDateStr, &endDateStr)
		if err != nil {
			continue
		}

		// Parse start_date
		var contractStartDate time.Time
		if startDateStr.Valid {
			contractStartDate, _ = time.Parse("2006-01-02", startDateStr.String)
		}

		// Parse end_date (vencimento do contrato)
		var contractEndDate time.Time
		hasEndDate := false
		if endDateStr.Valid {
			contractEndDate, _ = time.Parse("2006-01-02", endDateStr.String)
			hasEndDate = true
		}

		// Verificar se o período está dentro da vigência do contrato
		// Contrato deve ter começado antes ou no mês em questão
		if !contractStartDate.IsZero() && targetDate.Before(time.Date(contractStartDate.Year(), contractStartDate.Month(), 1, 0, 0, 0, 0, time.UTC)) {
			continue
		}

		// Se tem data de fim (vencimento), verificar se já expirou
		if hasEndDate && !contractEndDate.IsZero() {
			// Período deve ser antes ou no mesmo mês do vencimento
			contractEndMonth := time.Date(contractEndDate.Year(), contractEndDate.Month(), 1, 0, 0, 0, 0, time.UTC)
			if targetDate.After(contractEndMonth) {
				continue
			}
		}

		// Verificar se a recorrência se aplica a este mês
		shouldInclude := false
		switch recurrenceType {
		case "mensal":
			shouldInclude = true
		case "trimestral":
			// Calcular meses desde o início do contrato
			if !contractStartDate.IsZero() {
				startMonth := int(contractStartDate.Month())
				monthsSinceStart := (year-contractStartDate.Year())*12 + (month - startMonth)
				shouldInclude = monthsSinceStart >= 0 && monthsSinceStart%3 == 0
			} else {
				// Se não tem data de início, considerar meses padrão (janeiro, abril, julho, outubro)
				shouldInclude = month == 1 || month == 4 || month == 7 || month == 10
			}
		case "semestral":
			// Calcular meses desde o início do contrato
			if !contractStartDate.IsZero() {
				startMonth := int(contractStartDate.Month())
				monthsSinceStart := (year-contractStartDate.Year())*12 + (month - startMonth)
				shouldInclude = monthsSinceStart >= 0 && monthsSinceStart%6 == 0
			} else {
				// Se não tem data de início, considerar meses padrão (janeiro e julho)
				shouldInclude = month == 1 || month == 7
			}
		case "anual":
			// Calcular anos desde o início do contrato
			if !contractStartDate.IsZero() {
				startMonth := int(contractStartDate.Month())
				startYear := contractStartDate.Year()
				shouldInclude = year >= startYear && month == startMonth && (year-startYear) >= 0
			} else {
				// Se não tem data de início, considerar apenas janeiro
				shouldInclude = month == 1
			}
		}

		if shouldInclude {
			// Verificar se a cobrança já foi paga consultando installments
			// Para recorrentes que foram convertidos em parcelas
			dueDate := time.Date(year, time.Month(month), dueDay, 0, 0, 0, 0, time.UTC)
			if dueDay > 28 {
				// Ajustar para o último dia do mês se necessário
				lastDay := time.Date(year, time.Month(month+1), 0, 0, 0, 0, 0, time.UTC).Day()
				if dueDay > lastDay {
					dueDate = time.Date(year, time.Month(month), lastDay, 0, 0, 0, 0, time.UTC)
				}
			}

			// Verificar se há uma parcela correspondente (caso tenha sido criada manualmente)
			checkInstallment := `
				SELECT status FROM financial_installments
				WHERE contract_financial_id = $1
				AND EXTRACT(YEAR FROM due_date) = $2
				AND EXTRACT(MONTH FROM due_date) = $3
				LIMIT 1
			`
			var installmentStatus string
			err = s.db.QueryRow(checkInstallment, cfID, year, month).Scan(&installmentStatus)

			if err == nil {
				// Existe parcela, usar o status dela
				if installmentStatus == "pago" {
					ps.AlreadyReceived += receivedValue
					ps.PaidCount++
				} else if installmentStatus == "pendente" {
					ps.PendingAmount += receivedValue
					ps.PendingCount++
				} else if installmentStatus == "atrasado" {
					ps.OverdueAmount += receivedValue
					ps.OverdueCount++
				}
			} else {
				// Não existe parcela, considerar como pendente ou atrasado baseado na data
				now := time.Now()
				if dueDate.Before(now) {
					ps.OverdueAmount += receivedValue
					ps.OverdueCount++
				} else {
					ps.PendingAmount += receivedValue
					ps.PendingCount++
				}
			}

			ps.TotalToReceive += receivedValue
			ps.TotalClientPays += clientValue
		}
	}

	// Formatar período
	ps.Period = fmt.Sprintf("%04d-%02d", year, month)
	monthNames := []string{"", "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
		"Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"}
	ps.PeriodLabel = fmt.Sprintf("%s %d", monthNames[month], year)

	return &ps, nil
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
