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

// Open-Generic-Hub/backend/store/affiliate_store.go

package store

import (
	"Open-Generic-Hub/backend/domain"
	"errors"
	"strings"

	"database/sql"

	"github.com/google/uuid"
)

type AffiliateStore struct {
	db DBInterface
}

func NewAffiliateStore(db DBInterface) *AffiliateStore {
	return &AffiliateStore{
		db: db,
	}
}

func (s *AffiliateStore) CreateAffiliate(affiliate domain.Affiliate) (string, error) {
	// Validar afiliado usando validações do domínio
	validationErrors := domain.ValidateAffiliate(&affiliate)
	if validationErrors != nil {
		return "", validationErrors
	}

	trimmedName, err := ValidateName(affiliate.Name, 255)
	if err != nil {
		return "", err
	}
	if affiliate.ClientID == "" {
		return "", sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", affiliate.ClientID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("client does not exist")
	}
	// NOVA REGRA: Nome único por empresa
	err = s.db.QueryRow("SELECT COUNT(*) FROM affiliates WHERE client_id = $1 AND name = $2", affiliate.ClientID, trimmedName).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", errors.New("affiliate name must be unique per client")
	}

	// Default status to 'ativo' if not provided
	status := affiliate.Status
	if status == "" {
		status = "ativo"
	}

	newID := uuid.New().String()

	// Normalize all optional string fields (empty strings become NULL)
	description := normalizeOptionalString(affiliate.Description)
	email := normalizeOptionalString(affiliate.Email)
	phone := normalizeOptionalString(affiliate.Phone)
	address := normalizeOptionalString(affiliate.Address)
	notes := normalizeOptionalString(affiliate.Notes)
	tags := normalizeOptionalString(affiliate.Tags)
	contactPreference := normalizeOptionalString(affiliate.ContactPreference)
	documents := normalizeOptionalString(affiliate.Documents)

	sqlStatement := `INSERT INTO affiliates
		(id, name, client_id, description, birth_date, email, phone, address,
		 notes, status, tags, contact_preference, documents)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	_, err = s.db.Exec(sqlStatement, newID, trimmedName, affiliate.ClientID,
		description, affiliate.BirthDate, email, phone,
		address, notes, status, tags,
		contactPreference, documents)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetAffiliatesByClientID fetches ALL affiliates for a specific client.
func (s *AffiliateStore) GetAffiliatesByClientID(clientID string) (affiliates []domain.Affiliate, err error) {
	if clientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", clientID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return []domain.Affiliate{}, nil // No affiliates for non-existent client
	}

	sqlStatement := `SELECT id, name, client_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM affiliates WHERE client_id = $1`

	rows, err := s.db.Query(sqlStatement, clientID)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	affiliates = []domain.Affiliate{}
	for rows.Next() {
		var affiliate domain.Affiliate
		if err = rows.Scan(&affiliate.ID, &affiliate.Name, &affiliate.ClientID,
			&affiliate.Description, &affiliate.BirthDate, &affiliate.Email, &affiliate.Phone,
			&affiliate.Address, &affiliate.Notes, &affiliate.Status, &affiliate.Tags,
			&affiliate.ContactPreference, &affiliate.Documents); err != nil {
			return nil, err
		}
		affiliates = append(affiliates, affiliate)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return affiliates, nil
}

// GetAffiliatesByName busca afiliados por nome (case-insensitive, parcial) para um cliente específico
func (s *AffiliateStore) GetAffiliatesByName(clientID, name string) ([]domain.Affiliate, error) {
	name = strings.TrimSpace(name)
	if clientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, name, client_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM affiliates WHERE client_id = $1 AND LOWER(name) LIKE LOWER($2)`
	likePattern := "%" + name + "%"
	rows, err := s.db.Query(sqlStatement, clientID, likePattern)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()
	var affiliates []domain.Affiliate
	for rows.Next() {
		var affiliate domain.Affiliate
		if err = rows.Scan(&affiliate.ID, &affiliate.Name, &affiliate.ClientID,
			&affiliate.Description, &affiliate.BirthDate, &affiliate.Email, &affiliate.Phone,
			&affiliate.Address, &affiliate.Notes, &affiliate.Status, &affiliate.Tags,
			&affiliate.ContactPreference, &affiliate.Documents); err != nil {
			return nil, err
		}
		affiliates = append(affiliates, affiliate)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return affiliates, nil
}

// UpdateAffiliate atualiza os dados de um afiliado existente
func (s *AffiliateStore) UpdateAffiliate(affiliate domain.Affiliate) error {
	if affiliate.ID == "" {
		return sql.ErrNoRows // Or use errors.New("affiliate ID cannot be empty")
	}

	// Validar afiliado usando validações do domínio
	validationErrors := domain.ValidateAffiliate(&affiliate)
	if validationErrors != nil {
		return validationErrors
	}

	trimmedName, err := ValidateName(affiliate.Name, 255)
	if err != nil {
		return err
	}
	if affiliate.ClientID == "" {
		return sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", affiliate.ClientID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("client does not exist")
	}

	// Check if name is already taken by another affiliate of the same client
	err = s.db.QueryRow("SELECT COUNT(*) FROM affiliates WHERE client_id = $1 AND name = $2 AND id != $3",
		affiliate.ClientID, trimmedName, affiliate.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("affiliate name must be unique per client")
	}

	// Default status if empty
	status := affiliate.Status
	if status == "" {
		status = "ativo"
	}

	// Normalize all optional string fields (empty strings become NULL)
	description := normalizeOptionalString(affiliate.Description)
	email := normalizeOptionalString(affiliate.Email)
	phone := normalizeOptionalString(affiliate.Phone)
	address := normalizeOptionalString(affiliate.Address)
	notes := normalizeOptionalString(affiliate.Notes)
	tags := normalizeOptionalString(affiliate.Tags)
	contactPreference := normalizeOptionalString(affiliate.ContactPreference)
	documents := normalizeOptionalString(affiliate.Documents)

	sqlStatement := `UPDATE affiliates SET
		name = $1, client_id = $2, description = $3, birth_date = $4,
		email = $5, phone = $6, address = $7, notes = $8,
		status = $9, tags = $10, contact_preference = $11, documents = $12
		WHERE id = $13`
	result, err := s.db.Exec(sqlStatement, trimmedName, affiliate.ClientID,
		description, affiliate.BirthDate, email, phone,
		address, notes, status, tags,
		contactPreference, documents, affiliate.ID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// DeleteAffiliate remove um afiliado do banco de dados
func (s *AffiliateStore) DeleteAffiliate(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("affiliate ID cannot be empty")
	}
	// Check if affiliate exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM affiliates WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("affiliate does not exist")
	}
	// NOVA REGRA: Desassociar contratos antes de deletar afiliado
	_, err = s.db.Exec("UPDATE contracts SET affiliate_id = NULL WHERE affiliate_id = $1", id)
	if err != nil {
		return err
	}
	sqlStatement := `DELETE FROM affiliates WHERE id = $1`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// GetAffiliateByID busca um afiliado específico pelo seu ID
func (s *AffiliateStore) GetAffiliateByID(id string) (*domain.Affiliate, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("affiliate ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, client_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM affiliates WHERE id = $1`

	var affiliate domain.Affiliate
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&affiliate.ID,
		&affiliate.Name,
		&affiliate.ClientID,
		&affiliate.Description,
		&affiliate.BirthDate,
		&affiliate.Email,
		&affiliate.Phone,
		&affiliate.Address,
		&affiliate.Notes,
		&affiliate.Status,
		&affiliate.Tags,
		&affiliate.ContactPreference,
		&affiliate.Documents,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &affiliate, nil
}
