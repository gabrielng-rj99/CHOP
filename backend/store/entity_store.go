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

// Open-Generic-Hub/backend/store/client_store.go

package store

import (
	"Open-Generic-Hub/backend/domain"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type EntityStore struct {
	db DBInterface
}

func NewEntityStore(db DBInterface) *EntityStore {
	return &EntityStore{
		db: db,
	}
}

// CreateClient cria um novo cliente com todos os campos
func (s *EntityStore) CreateEntity(entity domain.Entity) (string, error) {
	// Validar cliente usando validações do domínio
	validationErrors := domain.ValidateEntity(&entity)
	if !validationErrors.IsValid() {
		return "", errors.New(validationErrors.Error())
	}

	// Trim and validate name
	trimmedName, err := ValidateName(entity.Name, 255)
	if err != nil {
		return "", err
	}

	// Check for duplicate name only if registration_id is NULL
	// If registration_id is provided, it will be the unique identifier
	var count int
	if entity.RegistrationID == nil {
		err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE name = $1 AND registration_id IS NULL", trimmedName).Scan(&count)
		if err != nil && err != sql.ErrNoRows {
			return "", err
		}
		if count > 0 {
			return "", errors.New("client name already exists (when registration ID is not provided, name must be unique)")
		}
	}

	// Validate and format registration ID if provided
	// Treat empty strings as NULL
	var formattedID *string
	if entity.RegistrationID != nil {
		trimmedRegID := strings.TrimSpace(*entity.RegistrationID)
		if trimmedRegID != "" {
			if !isValidCPFOrCNPJ(trimmedRegID) {
				return "", errors.New("registration ID must be a valid CPF or CNPJ")
			}
			formatted, err := FormatCPFOrCNPJ(trimmedRegID)
			if err != nil {
				return "", errors.New("registration ID must be a valid CPF or CNPJ")
			}

			// Check for duplicate registration ID
			err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE registration_id = $1", formatted).Scan(&count)
			if err != nil && err != sql.ErrNoRows {
				return "", err
			}
			if count > 0 {
				return "", errors.New("client registration ID already exists")
			}
			formattedID = &formatted
		}
		// If trimmedRegID is empty, formattedID stays nil
	}

	// Default status to 'inativo' - will be updated by UpdateEntityStatus based on agreements
	status := "inativo"

	newID := uuid.New().String()
	createdAt := time.Now()

	// Normalize all optional string fields (empty strings become NULL)
	nickname := normalizeOptionalString(entity.Nickname)
	email := normalizeOptionalString(entity.Email)
	phone := normalizeOptionalString(entity.Phone)
	address := normalizeOptionalString(entity.Address)
	notes := normalizeOptionalString(entity.Notes)
	tags := normalizeOptionalString(entity.Tags)
	contactPreference := normalizeOptionalString(entity.ContactPreference)
	documents := normalizeOptionalString(entity.Documents)

	sqlStatement := `INSERT INTO entities
		(id, name, registration_id, nickname, birth_date, email, phone, address, notes,
		 status, tags, contact_preference, last_contact_date, next_action_date, created_at, documents)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	_, err = s.db.Exec(sqlStatement,
		newID, trimmedName, formattedID, nickname, entity.BirthDate,
		email, phone, address, notes,
		status, tags, contactPreference, entity.LastContactDate,
		entity.NextActionDate, createdAt, documents)

	if err != nil {
		// Handle unique constraint violations
		if err.Error() != "" {
			if strings.Contains(err.Error(), "unique_registration_id") ||
				strings.Contains(err.Error(), "registration_id") {
				return "", errors.New("client registration ID already exists")
			}
			if strings.Contains(err.Error(), "unique_name_when_no_registration") {
				return "", errors.New("client name already exists (when registration ID is not provided, name must be unique)")
			}
		}
		return "", err
	}
	// Update client status based on active agreements
	if err := s.UpdateEntityStatus(newID); err != nil {
		// Non-critical, just log but don't fail
	}

	return newID, nil
}

// GetEntityByID retorna um cliente pelo ID
func (s *EntityStore) GetEntityByID(id string) (*domain.Entity, error) {
	if id == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM entities WHERE id = $1`
	row := s.db.QueryRow(sqlStatement, id)

	var entity domain.Entity
	err := row.Scan(&entity.ID, &entity.Name, &entity.RegistrationID, &entity.Nickname,
		&entity.BirthDate, &entity.Email, &entity.Phone, &entity.Address, &entity.Notes,
		&entity.Status, &entity.Tags, &entity.ContactPreference, &entity.LastContactDate,
		&entity.NextActionDate, &entity.CreatedAt, &entity.Documents, &entity.ArchivedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &entity, nil
}

// GetEntityNameByID returns only the client's name for a given ID.
func (s *EntityStore) GetEntityNameByID(id string) (string, error) {
	entity, err := s.GetEntityByID(id)
	if err != nil {
		return "", err
	}
	if entity == nil {
		return "", errors.New("client not found")
	}
	return entity.Name, nil
}

// GetEntitiesByName busca clientes por nome (case-insensitive, parcial)
func (s *EntityStore) GetEntitiesByName(name string) ([]domain.Entity, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM entities WHERE LOWER(name) LIKE LOWER($1) AND archived_at IS NULL`
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
	var entities []domain.Entity
	for rows.Next() {
		var entity domain.Entity
		if err = rows.Scan(&entity.ID, &entity.Name, &entity.RegistrationID, &entity.Nickname,
			&entity.BirthDate, &entity.Email, &entity.Phone, &entity.Address, &entity.Notes,
			&entity.Status, &entity.Tags, &entity.ContactPreference, &entity.LastContactDate,
			&entity.NextActionDate, &entity.CreatedAt, &entity.Documents, &entity.ArchivedAt); err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return entities, nil
}

// UpdateClient atualiza um cliente existente
func (s *EntityStore) UpdateEntity(entity domain.Entity) error {
	if entity.ID == "" {
		return errors.New("client ID cannot be empty")
	}

	// Validar cliente usando validações do domínio
	validationErrors := domain.ValidateEntity(&entity)
	if !validationErrors.IsValid() {
		return errors.New(validationErrors.Error())
	}

	// Status will be auto-calculated, ignore any status from client input

	// Trim and validate name
	trimmedName, err := ValidateName(entity.Name, 255)
	if err != nil {
		return err
	}

	// Check if name is already taken by another client (only when registration_id is NULL)
	var count int
	if entity.RegistrationID == nil {
		err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE name = $1 AND id != $2 AND registration_id IS NULL", trimmedName, entity.ID).Scan(&count)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if count > 0 {
			return errors.New("client name already exists (when registration ID is not provided, name must be unique)")
		}
	}

	// Validate and format registration ID if provided
	// Treat empty strings as NULL
	var formattedID *string
	if entity.RegistrationID != nil {
		trimmedRegID := strings.TrimSpace(*entity.RegistrationID)
		if trimmedRegID != "" {
			if !isValidCPFOrCNPJ(trimmedRegID) {
				return errors.New("registration ID must be a valid CPF or CNPJ")
			}
			formatted, err := FormatCPFOrCNPJ(trimmedRegID)
			if err != nil {
				return errors.New("registration ID must be a valid CPF or CNPJ")
			}

			// Check for duplicate registration ID (excluding current client)
			err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE registration_id = $1 AND id != $2",
				formatted, entity.ID).Scan(&count)
			if err != nil && err != sql.ErrNoRows {
				return err
			}
			if count > 0 {
				return errors.New("client registration ID already exists")
			}
			formattedID = &formatted
		}
		// If trimmedRegID is empty, formattedID stays nil
	}

	// Check if client exists
	err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1", entity.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client does not exist")
	}

	// Default status if empty
	status := entity.Status
	if status == "" {
		status = "ativo"
	}

	// Normalize all optional string fields (empty strings become NULL)
	nickname := normalizeOptionalString(entity.Nickname)
	email := normalizeOptionalString(entity.Email)
	phone := normalizeOptionalString(entity.Phone)
	address := normalizeOptionalString(entity.Address)
	notes := normalizeOptionalString(entity.Notes)
	tags := normalizeOptionalString(entity.Tags)
	contactPreference := normalizeOptionalString(entity.ContactPreference)
	documents := normalizeOptionalString(entity.Documents)

	sqlStatement := `UPDATE entities SET
		name = $1, registration_id = $2, nickname = $3, birth_date = $4,
		email = $5, phone = $6, address = $7, notes = $8,
		status = $9, tags = $10, contact_preference = $11,
		last_contact_date = $12, next_action_date = $13, documents = $14
		WHERE id = $15`

	result, err := s.db.Exec(sqlStatement,
		trimmedName, formattedID, nickname, entity.BirthDate,
		email, phone, address, notes,
		status, tags, contactPreference,
		entity.LastContactDate, entity.NextActionDate, documents,
		entity.ID)

	if err != nil {
		if err.Error() != "" {
			if strings.Contains(err.Error(), "unique_registration_id") ||
				strings.Contains(err.Error(), "registration_id") {
				return errors.New("client registration ID already exists")
			}
			if strings.Contains(err.Error(), "unique_name_when_no_registration") {
				return errors.New("client name already exists (when registration ID is not provided, name must be unique)")
			}
		}
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no client updated")
	}

	// Update client status based on active agreements
	if err := s.UpdateEntityStatus(entity.ID); err != nil {
		// Non-critical, just log but don't fail
	}

	return nil
}

// UpdateEntityStatus atualiza o status do cliente baseado nos contratos ativos
// Ignora clientes arquivados
func (s *EntityStore) UpdateEntityStatus(entityID string) error {
	if entityID == "" {
		return errors.New("client ID cannot be empty")
	}

	// Check if client is archived - don't update status for archived entities
	var archivedAt *time.Time
	err := s.db.QueryRow(`SELECT archived_at FROM entities WHERE id = $1`, entityID).Scan(&archivedAt)
	if err != nil {
		return err
	}
	if archivedAt != nil {
		return nil // Don't update status for archived entities
	}

	// Count active agreements (not archived and either no end_date or end_date in future)
	var activeAgreements int
	now := time.Now()
	err = s.db.QueryRow(`
		SELECT COUNT(*)
		FROM agreements
		WHERE entity_id = $1
		AND archived_at IS NULL
		AND (end_date IS NULL OR end_date > $2)
	`, entityID, now).Scan(&activeAgreements)
	if err != nil {
		return err
	}

	// Set status based on active agreements
	var newStatus string
	if activeAgreements > 0 {
		newStatus = "ativo"
	} else {
		newStatus = "inativo"
	}

	_, err = s.db.Exec(`UPDATE entities SET status = $1 WHERE id = $2`, newStatus, entityID)
	if err != nil {
		return err
	}

	return nil
}

// isValidCPFOrCNPJ validates CPF or CNPJ format and check digits
func isValidCPFOrCNPJ(id string) bool {
	id = strings.ReplaceAll(id, ".", "")
	id = strings.ReplaceAll(id, "-", "")
	id = strings.ReplaceAll(id, "/", "")
	id = strings.TrimSpace(id)

	if len(id) == 11 {
		return isValidCPF(id)
	}
	if len(id) == 14 {
		return isValidCNPJ(id)
	}
	return false
}

// isValidCPF checks CPF format and digits
func isValidCPF(cpf string) bool {
	if len(cpf) != 11 {
		return false
	}
	// Reject all digits equal
	for _, d := range []string{
		"00000000000", "11111111111", "22222222222", "33333333333",
		"44444444444", "55555555555", "66666666666", "77777777777",
		"88888888888", "99999999999",
	} {
		if cpf == d {
			return false
		}
	}
	// Validate check digits
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(cpf[i]-'0') * (10 - i)
	}
	d1 := (sum * 10) % 11
	if d1 == 10 {
		d1 = 0
	}
	if d1 != int(cpf[9]-'0') {
		return false
	}
	sum = 0
	for i := 0; i < 10; i++ {
		sum += int(cpf[i]-'0') * (11 - i)
	}
	d2 := (sum * 10) % 11
	if d2 == 10 {
		d2 = 0
	}
	return d2 == int(cpf[10]-'0')
}

// isValidCNPJ checks CNPJ format and digits
func isValidCNPJ(cnpj string) bool {
	if len(cnpj) != 14 {
		return false
	}
	// Reject all digits equal
	for _, d := range []string{
		"00000000000000", "11111111111111", "22222222222222", "33333333333333",
		"44444444444444", "55555555555555", "66666666666666", "77777777777777",
		"88888888888888", "99999999999999",
	} {
		if cnpj == d {
			return false
		}
	}
	var calc = func(cnpj string, length int) int {
		sum := 0
		weight := []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
		if length == 13 {
			weight = append([]int{6}, weight...)
		}
		for i := 0; i < length; i++ {
			sum += int(cnpj[i]-'0') * weight[i]
		}
		d := sum % 11
		if d < 2 {
			return 0
		}
		return 11 - d
	}
	d1 := calc(cnpj, 12)
	d2 := calc(cnpj, 13)
	return d1 == int(cnpj[12]-'0') && d2 == int(cnpj[13]-'0')
}

// --- NOVAS FUNÇÕES ---

// ArchiveEntity define a data de arquivamento para a data/hora atual.
// Além disso, arquiva todas as licenças permanentes do cliente (end_date >= 9999-01-01).
func (s *EntityStore) ArchiveEntity(id string) error {
	if id == "" {
		return errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}

	// Arquivar cliente
	sqlStatement := `UPDATE entities SET archived_at = $1 WHERE id = $2`
	result, err := s.db.Exec(sqlStatement, time.Now(), id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no client archived")
	}

	// Arquivar todos os contratos associados ao cliente (não só permanentes)
	_, err = s.db.Exec(
		`UPDATE agreements SET archived_at = $1 WHERE entity_id = $2 AND archived_at IS NULL`,
		time.Now(), id,
	)
	if err != nil {
		return err
	}

	return nil
}

// UnarchiveEntity define a data de arquivamento de volta para NULL.
func (s *EntityStore) UnarchiveEntity(id string) error {
	if id == "" {
		return errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}
	sqlStatement := `UPDATE entities SET archived_at = NULL WHERE id = $1`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no client unarchived")
	}
	return nil
}

// --- FUNÇÃO DE DELEÇÃO PERMANENTE ---
//
// DeleteEntityPermanently remove permanentemente um cliente e seus dados associados.
func (s *EntityStore) DeleteEntityPermanently(id string) error {
	if id == "" {
		return errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}
	// NOVA REGRA: Só pode excluir cliente se todos os contratos estiverem expirados ou arquivados
	var blockedContracts int
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM agreements
		WHERE entity_id = $1
		AND archived_at IS NULL
		AND end_date > $2
	`, id, time.Now()).Scan(&blockedContracts)
	if err != nil {
		return err
	}
	if blockedContracts > 0 {
		return errors.New("cannot delete client with active or unarchived agreements")
	}
	// Cascade delete: remover dependentes e contratos associados ao cliente
	_, err = s.db.Exec("DELETE FROM agreements WHERE entity_id = $1", id)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("DELETE FROM sub_entities WHERE entity_id = $1", id)
	if err != nil {
		return err
	}
	sqlStatement := `DELETE FROM entities WHERE id = $1`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no client deleted")
	}
	return nil
}

// GetAllEntities retorna todos os clientes não arquivados
func (s *EntityStore) GetAllEntities() (entities []domain.Entity, err error) {
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM entities WHERE archived_at IS NULL`

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
	for rows.Next() {
		var entity domain.Entity
		if err = rows.Scan(&entity.ID, &entity.Name, &entity.RegistrationID, &entity.Nickname,
			&entity.BirthDate, &entity.Email, &entity.Phone, &entity.Address, &entity.Notes,
			&entity.Status, &entity.Tags, &entity.ContactPreference, &entity.LastContactDate,
			&entity.NextActionDate, &entity.CreatedAt, &entity.Documents, &entity.ArchivedAt); err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return entities, nil
}

// GetArchivedEntities retorna todos os clientes arquivados
func (s *EntityStore) GetArchivedEntities() (entities []domain.Entity, err error) {
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM entities WHERE archived_at IS NOT NULL`

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

	for rows.Next() {
		var entity domain.Entity
		if err = rows.Scan(&entity.ID, &entity.Name, &entity.RegistrationID, &entity.Nickname,
			&entity.BirthDate, &entity.Email, &entity.Phone, &entity.Address, &entity.Notes,
			&entity.Status, &entity.Tags, &entity.ContactPreference, &entity.LastContactDate,
			&entity.NextActionDate, &entity.CreatedAt, &entity.Documents, &entity.ArchivedAt); err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return entities, nil
}

// GetAllEntitiesIncludingArchived retorna todos os clientes, incluindo os arquivados
func (s *EntityStore) GetAllEntitiesIncludingArchived() (entities []domain.Entity, err error) {
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM entities`

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

	for rows.Next() {
		var entity domain.Entity
		if err = rows.Scan(&entity.ID, &entity.Name, &entity.RegistrationID, &entity.Nickname,
			&entity.BirthDate, &entity.Email, &entity.Phone, &entity.Address, &entity.Notes,
			&entity.Status, &entity.Tags, &entity.ContactPreference, &entity.LastContactDate,
			&entity.NextActionDate, &entity.CreatedAt, &entity.Documents, &entity.ArchivedAt); err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return entities, nil
}
