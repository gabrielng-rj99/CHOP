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

type SubEntityStore struct {
	db DBInterface
}

func NewSubEntityStore(db DBInterface) *SubEntityStore {
	return &SubEntityStore{
		db: db,
	}
}

func (s *SubEntityStore) CreateSubEntity(subEntity domain.SubEntity) (string, error) {
	// Validar dependente usando validações do domínio
	validationErrors := domain.ValidateSubEntity(&subEntity)
	if !validationErrors.IsValid() {
		return "", errors.New(validationErrors.Error())
	}

	trimmedName, err := ValidateName(subEntity.Name, 255)
	if err != nil {
		return "", err
	}
	if subEntity.EntityID == "" {
		return "", sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1", subEntity.EntityID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("client does not exist")
	}
	// NOVA REGRA: Nome único por empresa
	err = s.db.QueryRow("SELECT COUNT(*) FROM sub_entities WHERE entity_id = $1 AND name = $2", subEntity.EntityID, trimmedName).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", errors.New("dependent name must be unique per client")
	}

	// Default status to 'ativo' if not provided
	status := subEntity.Status
	if status == "" {
		status = "ativo"
	}

	newID := uuid.New().String()

	// Normalize all optional string fields (empty strings become NULL)
	description := normalizeOptionalString(subEntity.Description)
	email := normalizeOptionalString(subEntity.Email)
	phone := normalizeOptionalString(subEntity.Phone)
	address := normalizeOptionalString(subEntity.Address)
	notes := normalizeOptionalString(subEntity.Notes)
	tags := normalizeOptionalString(subEntity.Tags)
	contactPreference := normalizeOptionalString(subEntity.ContactPreference)
	documents := normalizeOptionalString(subEntity.Documents)

	sqlStatement := `INSERT INTO sub_entities
		(id, name, entity_id, description, birth_date, email, phone, address,
		 notes, status, tags, contact_preference, documents)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	_, err = s.db.Exec(sqlStatement, newID, trimmedName, subEntity.EntityID,
		description, subEntity.BirthDate, email, phone,
		address, notes, status, tags,
		contactPreference, documents)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetSubEntitiesByEntityID fetches ALL sub_entities for a specific client.
func (s *SubEntityStore) GetSubEntitiesByEntityID(entityID string) (sub_entities []domain.SubEntity, err error) {
	if entityID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1", entityID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return []domain.SubEntity{}, nil // No sub_entities for non-existent client
	}

	sqlStatement := `SELECT id, name, entity_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM sub_entities WHERE entity_id = $1`

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

	sub_entities = []domain.SubEntity{}
	for rows.Next() {
		var subEntity domain.SubEntity
		if err = rows.Scan(&subEntity.ID, &subEntity.Name, &subEntity.EntityID,
			&subEntity.Description, &subEntity.BirthDate, &subEntity.Email, &subEntity.Phone,
			&subEntity.Address, &subEntity.Notes, &subEntity.Status, &subEntity.Tags,
			&subEntity.ContactPreference, &subEntity.Documents); err != nil {
			return nil, err
		}
		sub_entities = append(sub_entities, subEntity)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return sub_entities, nil
}

// GetDependentsByName busca dependentes por nome (case-insensitive, parcial) para um cliente específico
func (s *SubEntityStore) GetDependentsByName(entityID, name string) ([]domain.SubEntity, error) {
	name = strings.TrimSpace(name)
	if entityID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, name, entity_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM sub_entities WHERE entity_id = $1 AND LOWER(name) LIKE LOWER($2)`
	likePattern := "%" + name + "%"
	rows, err := s.db.Query(sqlStatement, entityID, likePattern)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()
	var sub_entities []domain.SubEntity
	for rows.Next() {
		var subEntity domain.SubEntity
		if err = rows.Scan(&subEntity.ID, &subEntity.Name, &subEntity.EntityID,
			&subEntity.Description, &subEntity.BirthDate, &subEntity.Email, &subEntity.Phone,
			&subEntity.Address, &subEntity.Notes, &subEntity.Status, &subEntity.Tags,
			&subEntity.ContactPreference, &subEntity.Documents); err != nil {
			return nil, err
		}
		sub_entities = append(sub_entities, subEntity)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return sub_entities, nil
}

// UpdateSubEntity atualiza os dados de um dependente existente
func (s *SubEntityStore) UpdateSubEntity(subEntity domain.SubEntity) error {
	if subEntity.ID == "" {
		return sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}

	// Validar dependente usando validações do domínio
	validationErrors := domain.ValidateSubEntity(&subEntity)
	if !validationErrors.IsValid() {
		return errors.New(validationErrors.Error())
	}

	trimmedName, err := ValidateName(subEntity.Name, 255)
	if err != nil {
		return err
	}
	if subEntity.EntityID == "" {
		return sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1", subEntity.EntityID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("client does not exist")
	}

	// Check if name is already taken by another dependent of the same client
	err = s.db.QueryRow("SELECT COUNT(*) FROM sub_entities WHERE entity_id = $1 AND name = $2 AND id != $3",
		subEntity.EntityID, trimmedName, subEntity.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("dependent name must be unique per client")
	}

	// Default status if empty
	status := subEntity.Status
	if status == "" {
		status = "ativo"
	}

	// Normalize all optional string fields (empty strings become NULL)
	description := normalizeOptionalString(subEntity.Description)
	email := normalizeOptionalString(subEntity.Email)
	phone := normalizeOptionalString(subEntity.Phone)
	address := normalizeOptionalString(subEntity.Address)
	notes := normalizeOptionalString(subEntity.Notes)
	tags := normalizeOptionalString(subEntity.Tags)
	contactPreference := normalizeOptionalString(subEntity.ContactPreference)
	documents := normalizeOptionalString(subEntity.Documents)

	sqlStatement := `UPDATE sub_entities SET
		name = $1, entity_id = $2, description = $3, birth_date = $4,
		email = $5, phone = $6, address = $7, notes = $8,
		status = $9, tags = $10, contact_preference = $11, documents = $12
		WHERE id = $13`
	result, err := s.db.Exec(sqlStatement, trimmedName, subEntity.EntityID,
		description, subEntity.BirthDate, email, phone,
		address, notes, status, tags,
		contactPreference, documents, subEntity.ID)
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

// DeleteSubEntity remove um dependente do banco de dados
func (s *SubEntityStore) DeleteSubEntity(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}
	// Check if dependent exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM sub_entities WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("dependent does not exist")
	}
	// NOVA REGRA: Desassociar contratos antes de deletar dependente
	_, err = s.db.Exec("UPDATE agreements SET sub_entity_id = NULL WHERE sub_entity_id = $1", id)
	if err != nil {
		return err
	}
	sqlStatement := `DELETE FROM sub_entities WHERE id = $1`
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

// GetSubEntityByID busca um dependente específico pelo seu ID
func (s *SubEntityStore) GetSubEntityByID(id string) (*domain.SubEntity, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, entity_id, description, birth_date, email, phone,
		address, notes, status, tags, contact_preference, documents
		FROM sub_entities WHERE id = $1`

	var subEntity domain.SubEntity
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&subEntity.ID,
		&subEntity.Name,
		&subEntity.EntityID,
		&subEntity.Description,
		&subEntity.BirthDate,
		&subEntity.Email,
		&subEntity.Phone,
		&subEntity.Address,
		&subEntity.Notes,
		&subEntity.Status,
		&subEntity.Tags,
		&subEntity.ContactPreference,
		&subEntity.Documents,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &subEntity, nil
}
