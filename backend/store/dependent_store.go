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

// Open-Generic-Hub/backend/store/dependent_store.go

package store

import (
	domain "Open-Generic-Hub/backend/domain"
	"errors"
	"strings"

	"database/sql"

	"github.com/google/uuid"
)

type DependentStore struct {
	db DBInterface
}

func NewDependentStore(db DBInterface) *DependentStore {
	return &DependentStore{
		db: db,
	}
}

func (s *DependentStore) CreateDependent(dependent domain.Dependent) (string, error) {
	// Validar dependente usando validações do domínio
	validationErrors := domain.ValidateDependent(&dependent)
	if !validationErrors.IsValid() {
		return "", errors.New(validationErrors.Error())
	}

	trimmedName, err := ValidateName(dependent.Name, 255)
	if err != nil {
		return "", err
	}
	if dependent.ClientID == "" {
		return "", sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", dependent.ClientID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("client does not exist")
	}
	// NOVA REGRA: Nome único por empresa
	err = s.db.QueryRow("SELECT COUNT(*) FROM dependents WHERE client_id = $1 AND name = $2", dependent.ClientID, trimmedName).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", errors.New("dependent name must be unique per client")
	}

	// Default status to 'ativo' if not provided
	status := dependent.Status
	if status == "" {
		status = "ativo"
	}

	newID := uuid.New().String()

	// Normalize all optional string fields (empty strings become NULL)
	description := normalizeOptionalString(dependent.Description)
	email := normalizeOptionalString(dependent.Email)
	phone := normalizeOptionalString(dependent.Phone)
	address := normalizeOptionalString(dependent.Address)
	notes := normalizeOptionalString(dependent.Notes)
	tags := normalizeOptionalString(dependent.Tags)
	contactPreference := normalizeOptionalString(dependent.ContactPreference)
	documents := normalizeOptionalString(dependent.Documents)

	sqlStatement := `INSERT INTO dependents
		(id, name, client_id, description, birth_date, email, phone, address,
		 notes, status, tags, contact_preference, documents)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	_, err = s.db.Exec(sqlStatement, newID, trimmedName, dependent.ClientID,
		description, dependent.BirthDate, email, phone,
		address, notes, status, tags,
		contactPreference, documents)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetDependentsByClientID fetches ALL dependents for a specific client.
func (s *DependentStore) GetDependentsByClientID(clientID string) (dependents []domain.Dependent, err error) {
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
		return []domain.Dependent{}, nil // No dependents for non-existent client
	}

	sqlStatement := `SELECT id, name, client_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM dependents WHERE client_id = $1`

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

	dependents = []domain.Dependent{}
	for rows.Next() {
		var dependent domain.Dependent
		if err = rows.Scan(&dependent.ID, &dependent.Name, &dependent.ClientID,
			&dependent.Description, &dependent.BirthDate, &dependent.Email, &dependent.Phone,
			&dependent.Address, &dependent.Notes, &dependent.Status, &dependent.Tags,
			&dependent.ContactPreference, &dependent.Documents); err != nil {
			return nil, err
		}
		dependents = append(dependents, dependent)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return dependents, nil
}

// GetDependentsByName busca dependentes por nome (case-insensitive, parcial) para um cliente específico
func (s *DependentStore) GetDependentsByName(clientID, name string) ([]domain.Dependent, error) {
	name = strings.TrimSpace(name)
	if clientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, name, client_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM dependents WHERE client_id = $1 AND LOWER(name) LIKE LOWER($2)`
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
	var dependents []domain.Dependent
	for rows.Next() {
		var dependent domain.Dependent
		if err = rows.Scan(&dependent.ID, &dependent.Name, &dependent.ClientID,
			&dependent.Description, &dependent.BirthDate, &dependent.Email, &dependent.Phone,
			&dependent.Address, &dependent.Notes, &dependent.Status, &dependent.Tags,
			&dependent.ContactPreference, &dependent.Documents); err != nil {
			return nil, err
		}
		dependents = append(dependents, dependent)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return dependents, nil
}

// UpdateDependent atualiza os dados de um dependente existente
func (s *DependentStore) UpdateDependent(dependent domain.Dependent) error {
	if dependent.ID == "" {
		return sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}

	// Validar dependente usando validações do domínio
	validationErrors := domain.ValidateDependent(&dependent)
	if !validationErrors.IsValid() {
		return errors.New(validationErrors.Error())
	}

	trimmedName, err := ValidateName(dependent.Name, 255)
	if err != nil {
		return err
	}
	if dependent.ClientID == "" {
		return sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", dependent.ClientID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("client does not exist")
	}

	// Check if name is already taken by another dependent of the same client
	err = s.db.QueryRow("SELECT COUNT(*) FROM dependents WHERE client_id = $1 AND name = $2 AND id != $3",
		dependent.ClientID, trimmedName, dependent.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("dependent name must be unique per client")
	}

	// Default status if empty
	status := dependent.Status
	if status == "" {
		status = "ativo"
	}

	// Normalize all optional string fields (empty strings become NULL)
	description := normalizeOptionalString(dependent.Description)
	email := normalizeOptionalString(dependent.Email)
	phone := normalizeOptionalString(dependent.Phone)
	address := normalizeOptionalString(dependent.Address)
	notes := normalizeOptionalString(dependent.Notes)
	tags := normalizeOptionalString(dependent.Tags)
	contactPreference := normalizeOptionalString(dependent.ContactPreference)
	documents := normalizeOptionalString(dependent.Documents)

	sqlStatement := `UPDATE dependents SET
		name = $1, client_id = $2, description = $3, birth_date = $4,
		email = $5, phone = $6, address = $7, notes = $8,
		status = $9, tags = $10, contact_preference = $11, documents = $12
		WHERE id = $13`
	result, err := s.db.Exec(sqlStatement, trimmedName, dependent.ClientID,
		description, dependent.BirthDate, email, phone,
		address, notes, status, tags,
		contactPreference, documents, dependent.ID)
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

// DeleteDependent remove um dependente do banco de dados
func (s *DependentStore) DeleteDependent(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}
	// Check if dependent exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM dependents WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("dependent does not exist")
	}
	// NOVA REGRA: Desassociar contratos antes de deletar dependente
	_, err = s.db.Exec("UPDATE contracts SET dependent_id = NULL WHERE dependent_id = $1", id)
	if err != nil {
		return err
	}
	sqlStatement := `DELETE FROM dependents WHERE id = $1`
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

// GetDependentByID busca um dependente específico pelo seu ID
func (s *DependentStore) GetDependentByID(id string) (*domain.Dependent, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, client_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM dependents WHERE id = $1`

	var dependent domain.Dependent
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&dependent.ID,
		&dependent.Name,
		&dependent.ClientID,
		&dependent.Description,
		&dependent.BirthDate,
		&dependent.Email,
		&dependent.Phone,
		&dependent.Address,
		&dependent.Notes,
		&dependent.Status,
		&dependent.Tags,
		&dependent.ContactPreference,
		&dependent.Documents,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &dependent, nil
}
