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

// Open-Generic-Hub/backend/store/contract_store.go

package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"Open-Generic-Hub/backend/domain" // Use o nome do seu módulo

	"github.com/google/uuid"
)

// AgreementStats representa estatísticas de contratos por cliente
type AgreementStats struct {
	EntityID          string `json:"entity_id"`
	ActiveAgreements   int    `json:"active_agreements"`
	ExpiredAgreements  int    `json:"expired_agreements"`
	ArchivedAgreements int    `json:"archived_agreements"`
}

// AgreementStore é a nossa "caixa de ferramentas" para operações com a tabela agreements.
type AgreementStore struct {
	db DBInterface
}

// NewAgreementStore cria uma nova instância de AgreementStore.
func NewAgreementStore(db DBInterface) *AgreementStore {
	return &AgreementStore{
		db: db,
	}
}

// CreateAgreement insere um novo contrato no banco de dados.
func (s *AgreementStore) CreateAgreement(agreement domain.Agreement) (string, error) {
	// Model and ItemKey are now optional
	var trimmedModel, trimmedItemKey string
	var err error
	if agreement.Model != "" {
		trimmedModel, err = ValidateName(agreement.Model, 255)
		if err != nil {
			return "", err
		}
	}
	if agreement.ItemKey != "" {
		trimmedItemKey, err = ValidateName(agreement.ItemKey, 255)
		if err != nil {
			return "", err
		}
	}

	// Start and End dates are now optional - only validate if both are provided
	if agreement.StartDate != nil && agreement.EndDate != nil {
		if agreement.EndDate.Before(*agreement.StartDate) || agreement.EndDate.Equal(*agreement.StartDate) {
			return "", errors.New("end date must be after start date")
		}
	}

	if agreement.SubcategoryID == "" {
		return "", errors.New("line ID cannot be empty")
	}
	if agreement.EntityID == "" {
		return "", errors.New("client ID cannot be empty")
	}

	// Check if line exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE id = $1", agreement.SubcategoryID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", errors.New("line does not exist")
	}

	// Check if client exists e não está arquivado
	err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1 AND archived_at IS NULL", agreement.EntityID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", errors.New("client does not exist or is archived")
	}

	// If subEntityID is provided, check if dependent exists and belongs to the client
	if agreement.SubEntityID != nil && *agreement.SubEntityID != "" {
		err = s.db.QueryRow("SELECT COUNT(*) FROM sub_entities WHERE id = $1 AND entity_id = $2", *agreement.SubEntityID, agreement.EntityID).Scan(&count)
		if err != nil {
			return "", err
		}
		if count == 0 {
			return "", errors.New("dependent does not exist or does not belong to the specified client")
		}
	}

	// Check for duplicate product key only if provided
	if agreement.ItemKey != "" {
		err = s.db.QueryRow("SELECT COUNT(*) FROM agreements WHERE item_key = $1", agreement.ItemKey).Scan(&count)
		if err != nil {
			return "", err
		}
		if count > 0 {
			return "", errors.New("product key already exists")
		}
	}

	// NOVA REGRA: Verificar sobreposição temporal apenas se ambas as datas forem fornecidas
	if agreement.StartDate != nil && agreement.EndDate != nil {
		var overlapCount int
		if agreement.SubEntityID != nil && *agreement.SubEntityID != "" {
			err = s.db.QueryRow(`
				SELECT COUNT(*) FROM agreements
				WHERE subcategory_id = $1 AND entity_id = $2 AND sub_entity_id = $3
				AND start_date IS NOT NULL AND end_date IS NOT NULL
				AND (
					(start_date <= $4 AND end_date >= $5) OR
					(start_date <= $6 AND end_date >= $7)
				)
			`, agreement.SubcategoryID, agreement.EntityID, *agreement.SubEntityID,
				*agreement.EndDate, *agreement.EndDate,
				*agreement.StartDate, *agreement.StartDate,
			).Scan(&overlapCount)
		} else {
			err = s.db.QueryRow(`
				SELECT COUNT(*) FROM agreements
				WHERE subcategory_id = $1 AND entity_id = $2 AND sub_entity_id IS NULL
				AND start_date IS NOT NULL AND end_date IS NOT NULL
				AND (
					(start_date <= $3 AND end_date >= $4) OR
					(start_date <= $5 AND end_date >= $6)
				)
			`, agreement.SubcategoryID, agreement.EntityID,
				*agreement.EndDate, *agreement.EndDate,
				*agreement.StartDate, *agreement.StartDate,
			).Scan(&overlapCount)
		}
		if err != nil {
			return "", err
		}
		if overlapCount > 0 {
			return "", errors.New("contract period overlaps with another contract of the same type for this client/dependent")
		}
	}

	newID := uuid.New().String()
	sqlStatement := `
		INSERT INTO agreements (id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = s.db.Exec(sqlStatement,
		newID,
		trimmedModel,
		trimmedItemKey,
		nullTimeFromTime(agreement.StartDate),
		nullTimeFromTime(agreement.EndDate),
		agreement.SubcategoryID,
		agreement.EntityID,
		agreement.SubEntityID,
	)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// Helper function to convert *time.Time to sql.NullTime
func nullTimeFromTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// GetAgreementsByEntityID fetches all agreements for a specific client.
func (s *AgreementStore) GetAgreementsByEntityID(entityID string) (agreements []domain.Agreement, err error) {
	if entityID == "" {
		return nil, errors.New("client ID is required")
	}
	// Check if client exists and is not archived
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1 AND archived_at IS NULL", entityID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("client not found or archived")
	}

	sqlStatement := `SELECT id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id FROM agreements WHERE entity_id = $1`
	rows, err := s.db.Query(sqlStatement, entityID)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	agreements = []domain.Agreement{}
	for rows.Next() {
		var c domain.Agreement
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ItemKey, &startDate, &endDate, &c.SubcategoryID, &c.EntityID, &c.SubEntityID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			t := startDate.Time
			c.StartDate = &t
		}
		if endDate.Valid {
			t := endDate.Time
			c.EndDate = &t
		}
		agreements = append(agreements, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return agreements, nil
}

// GetAgreementsExpiringSoon busca contratos que expiram nos próximos 'days' dias.
func (s *AgreementStore) GetAgreementsExpiringSoon(days int) (agreements []domain.Agreement, err error) {
	now := time.Now()
	limitDate := now.AddDate(0, 0, days)

	sqlStatement := `SELECT id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id
	                 FROM agreements
	                 WHERE end_date BETWEEN $1 AND $2 AND archived_at IS NULL`

	rows, err := s.db.Query(sqlStatement, now, limitDate)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	agreements = []domain.Agreement{}
	for rows.Next() {
		var c domain.Agreement
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ItemKey, &startDate, &endDate, &c.SubcategoryID, &c.EntityID, &c.SubEntityID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			t := startDate.Time
			c.StartDate = &t
		}
		if endDate.Valid {
			t := endDate.Time
			c.EndDate = &t
		}
		agreements = append(agreements, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return agreements, nil
}

// GetAgreementsNotStarted busca contratos que ainda não iniciaram (start_date no futuro)
func (s *AgreementStore) GetAgreementsNotStarted() (agreements []domain.Agreement, err error) {
	now := time.Now()

	sqlStatement := `SELECT id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id
	                 FROM agreements
	                 WHERE start_date > $1 AND archived_at IS NULL`

	rows, err := s.db.Query(sqlStatement, now)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	agreements = []domain.Agreement{}
	for rows.Next() {
		var c domain.Agreement
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ItemKey, &startDate, &endDate, &c.SubcategoryID, &c.EntityID, &c.SubEntityID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			t := startDate.Time
			c.StartDate = &t
		}
		if endDate.Valid {
			t := endDate.Time
			c.EndDate = &t
		}
		agreements = append(agreements, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return agreements, nil
}

func (s *AgreementStore) UpdateAgreement(agreement domain.Agreement) error {
	if agreement.ID == "" {
		return errors.New("contract ID cannot be empty")
	}

	// Model and ItemKey are now optional
	var trimmedModel, trimmedItemKey string
	var err error
	if agreement.Model != "" {
		trimmedModel, err = ValidateName(agreement.Model, 255)
		if err != nil {
			return err
		}
	}
	if agreement.ItemKey != "" {
		trimmedItemKey, err = ValidateName(agreement.ItemKey, 255)
		if err != nil {
			return err
		}
	}

	// Datas são opcionais, mas se ambas forem fornecidas, end_date deve ser maior que start_date
	if agreement.StartDate != nil && agreement.EndDate != nil {
		if agreement.EndDate.Before(*agreement.StartDate) || agreement.EndDate.Equal(*agreement.StartDate) {
			return errors.New("end date must be after start date")
		}
	}

	// If subEntityID is provided, check if dependent exists and belongs to the client
	if agreement.SubEntityID != nil && *agreement.SubEntityID != "" {
		var depCount int
		err = s.db.QueryRow("SELECT COUNT(*) FROM sub_entities WHERE id = $1 AND entity_id = $2", *agreement.SubEntityID, agreement.EntityID).Scan(&depCount)
		if err != nil {
			return err
		}
		if depCount == 0 {
			return errors.New("dependent does not exist or does not belong to the specified client")
		}
	}

	// Check if contract exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM agreements WHERE id = $1", agreement.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("contract does not exist")
	}

	sqlStatement := `UPDATE agreements SET model = $1, item_key = $2, start_date = $3, end_date = $4 WHERE id = $5`
	result, err := s.db.Exec(sqlStatement, trimmedModel, trimmedItemKey,
		nullTimeFromTime(agreement.StartDate),
		nullTimeFromTime(agreement.EndDate),
		agreement.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no contract updated")
	}
	return nil
}

// GetAgreementStatsByEntityID retorna estatísticas de contratos de um cliente específico
func (s *AgreementStore) GetAgreementStatsByEntityID(entityID string) (*AgreementStats, error) {
	if entityID == "" {
		return nil, errors.New("client ID cannot be empty")
	}

	stats := &AgreementStats{
		EntityID: entityID,
	}

	now := time.Now()

	// Count active agreements (not archived and not expired)
	err := s.db.QueryRow(`
		SELECT COUNT(*)
		FROM agreements
		WHERE entity_id = $1
		AND archived_at IS NULL
		AND end_date > $2
	`, entityID, now).Scan(&stats.ActiveAgreements)
	if err != nil {
		return nil, err
	}

	// Count expired agreements (not archived but expired)
	err = s.db.QueryRow(`
		SELECT COUNT(*)
		FROM agreements
		WHERE entity_id = $1
		AND archived_at IS NULL
		AND end_date <= $2
	`, entityID, now).Scan(&stats.ExpiredAgreements)
	if err != nil {
		return nil, err
	}

	// Count archived agreements
	err = s.db.QueryRow(`
		SELECT COUNT(*)
		FROM agreements
		WHERE entity_id = $1
		AND archived_at IS NOT NULL
	`, entityID).Scan(&stats.ArchivedAgreements)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// GetAgreementStatsForAllEntities retorna estatísticas de contratos para todos os clientes
func (s *AgreementStore) GetAgreementStatsForAllEntities() (map[string]*AgreementStats, error) {
	now := time.Now()

	rows, err := s.db.Query(`
		SELECT
			entity_id,
			COUNT(CASE WHEN archived_at IS NULL AND (end_date IS NULL OR end_date > $1) THEN 1 END) as active,
			COUNT(CASE WHEN archived_at IS NULL AND end_date IS NOT NULL AND end_date <= $1 THEN 1 END) as expired,
			COUNT(CASE WHEN archived_at IS NOT NULL THEN 1 END) as archived
		FROM agreements
		GROUP BY entity_id
	`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	statsMap := make(map[string]*AgreementStats)
	for rows.Next() {
		var stats AgreementStats
		if err := rows.Scan(&stats.EntityID, &stats.ActiveAgreements, &stats.ExpiredAgreements, &stats.ArchivedAgreements); err != nil {
			return nil, err
		}
		statsMap[stats.EntityID] = &stats
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return statsMap, nil
}

// GetAgreementByID busca um contrato específico pelo seu ID
func (s *AgreementStore) GetAgreementByID(id string) (*domain.Agreement, error) {
	if id == "" {
		return nil, errors.New("contract ID cannot be empty")
	}
	sqlStatement := `
		SELECT id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id
		FROM agreements
		WHERE id = $1`

	var agreement domain.Agreement
	var startDate, endDate sql.NullTime
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&agreement.ID,
		&agreement.Model,
		&agreement.ItemKey,
		&startDate,
		&endDate,
		&agreement.SubcategoryID,
		&agreement.EntityID,
		&agreement.SubEntityID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if startDate.Valid {
		t := startDate.Time
		agreement.StartDate = &t
	}
	if endDate.Valid {
		t := endDate.Time
		agreement.EndDate = &t
	}

	return &agreement, nil
}

// Utility: Get explicit status for a contract (ativo, expirando, expirado)
// Uses time.Now() internally, so timing can matter in tests
// EndDate nil = infinito superior (nunca expira)
// StartDate nil = infinito inferior (começou sempre)
func GetAgreementStatus(agreement domain.Agreement) string {
	now := time.Now()

	// EndDate nil = nunca expira, sempre ativo
	if agreement.EndDate == nil {
		return "ativo"
	}

	if agreement.EndDate.Before(now) {
		return "expirado"
	}

	// Agreement is expiring if it expires within 30 days
	daysUntilExpiry := agreement.EndDate.Sub(now).Hours() / 24
	if daysUntilExpiry > 0 && daysUntilExpiry <= 30 {
		return "expirando"
	}

	return "ativo"
}

func (s *AgreementStore) DeleteAgreement(id string) error {
	if id == "" {
		return errors.New("contract ID cannot be empty")
	}
	// Check if contract exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM agreements WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("contract does not exist")
	}
	sqlStatement := `DELETE FROM agreements WHERE id = $1`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no contract deleted")
	}
	return nil
}

// GetAllAgreements fetches all agreements in the system (excluding archived)
func (s *AgreementStore) GetAllAgreements() (agreements []domain.Agreement, err error) {
	sqlStatement := `SELECT id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id
	                 FROM agreements WHERE archived_at IS NULL`
	rows, err := s.db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	agreements = []domain.Agreement{}
	for rows.Next() {
		var c domain.Agreement
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ItemKey, &startDate, &endDate, &c.SubcategoryID, &c.EntityID, &c.SubEntityID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			t := startDate.Time
			c.StartDate = &t
		}
		if endDate.Valid {
			t := endDate.Time
			c.EndDate = &t
		}
		agreements = append(agreements, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return agreements, nil
}

// GetAllAgreementsIncludingArchived fetches all agreements in the system (including archived)
func (s *AgreementStore) GetAllAgreementsIncludingArchived() (agreements []domain.Agreement, err error) {
	sqlStatement := `SELECT id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id, archived_at
	                 FROM agreements`
	rows, err := s.db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	agreements = []domain.Agreement{}
	for rows.Next() {
		var c domain.Agreement
		var startDate, endDate, archivedAt sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ItemKey, &startDate, &endDate, &c.SubcategoryID, &c.EntityID, &c.SubEntityID, &archivedAt); err != nil {
			return nil, err
		}
		if startDate.Valid {
			t := startDate.Time
			c.StartDate = &t
		}
		if endDate.Valid {
			t := endDate.Time
			c.EndDate = &t
		}
		if archivedAt.Valid {
			c.ArchivedAt = &archivedAt.Time
		}
		agreements = append(agreements, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return agreements, nil
}

// GetAgreementsByName fetches agreements by partial name/model (case-insensitive)
func (s *AgreementStore) GetAgreementsByName(name string) ([]domain.Agreement, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	// Busca case-insensitive já funcionará com CITEXT
	sqlStatement := `SELECT id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id
	                 FROM agreements WHERE model LIKE $1`
	likePattern := "%" + name + "%"
	rows, err := s.db.Query(sqlStatement, likePattern)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()
	var agreements []domain.Agreement
	for rows.Next() {
		var c domain.Agreement
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ItemKey, &startDate, &endDate, &c.SubcategoryID, &c.EntityID, &c.SubEntityID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			t := startDate.Time
			c.StartDate = &t
		}
		if endDate.Valid {
			t := endDate.Time
			c.EndDate = &t
		}
		agreements = append(agreements, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return agreements, nil
}

// GetAgreementsBySubcategoryID fetches all agreements for a specific line
func (s *AgreementStore) GetAgreementsBySubcategoryID(subcategoryID string) (agreements []domain.Agreement, err error) {
	if subcategoryID == "" {
		return nil, errors.New("line ID is required")
	}
	// Check if line exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE id = $1", subcategoryID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("line not found")
	}

	sqlStatement := `SELECT id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id
	                 FROM agreements WHERE subcategory_id = $1`
	rows, err := s.db.Query(sqlStatement, subcategoryID)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	agreements = []domain.Agreement{}
	for rows.Next() {
		var c domain.Agreement
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ItemKey, &startDate, &endDate, &c.SubcategoryID, &c.EntityID, &c.SubEntityID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			t := startDate.Time
			c.StartDate = &t
		}
		if endDate.Valid {
			t := endDate.Time
			c.EndDate = &t
		}
		agreements = append(agreements, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return agreements, nil
}

// GetAgreementsByCategoryID fetches all agreements for a specific category
func (s *AgreementStore) GetAgreementsByCategoryID(categoryID string) (agreements []domain.Agreement, err error) {
	if categoryID == "" {
		return nil, errors.New("category ID is required")
	}
	// Check if category exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", categoryID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("category not found")
	}

	sqlStatement := `
		SELECT c.id, c.model, c.item_key, c.start_date, c.end_date, c.subcategory_id, c.entity_id, c.sub_entity_id
		FROM agreements c
		INNER JOIN subcategories ln ON c.subcategory_id = ln.id
		WHERE ln.category_id = $1`
	rows, err := s.db.Query(sqlStatement, categoryID)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	agreements = []domain.Agreement{}
	for rows.Next() {
		var c domain.Agreement
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ItemKey, &startDate, &endDate, &c.SubcategoryID, &c.EntityID, &c.SubEntityID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			t := startDate.Time
			c.StartDate = &t
		}
		if endDate.Valid {
			t := endDate.Time
			c.EndDate = &t
		}
		agreements = append(agreements, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return agreements, nil
}
