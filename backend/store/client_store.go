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

type ClientStore struct {
	db DBInterface
}

func NewClientStore(db DBInterface) *ClientStore {
	return &ClientStore{
		db: db,
	}
}

// CreateClient cria um novo cliente com todos os campos
func (s *ClientStore) CreateClient(client domain.Client) (string, error) {
	// Validar cliente usando validações do domínio
	validationErrors := domain.ValidateClient(&client)
	if !validationErrors.IsValid() {
		return "", errors.New(validationErrors.Error())
	}

	// Trim and validate name
	trimmedName, err := ValidateName(client.Name, 255)
	if err != nil {
		return "", err
	}

	// Check for duplicate name only if registration_id is NULL
	// If registration_id is provided, it will be the unique identifier
	var count int
	if client.RegistrationID == nil {
		err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE name = $1 AND registration_id IS NULL", trimmedName).Scan(&count)
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
	if client.RegistrationID != nil {
		trimmedRegID := strings.TrimSpace(*client.RegistrationID)
		if trimmedRegID != "" {
			if !isValidCPFOrCNPJ(trimmedRegID) {
				return "", errors.New("registration ID must be a valid CPF or CNPJ")
			}
			formatted, err := FormatCPFOrCNPJ(trimmedRegID)
			if err != nil {
				return "", errors.New("registration ID must be a valid CPF or CNPJ")
			}

			// Check for duplicate registration ID
			err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE registration_id = $1", formatted).Scan(&count)
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

	// Default status to 'inativo' - will be updated by UpdateClientStatus based on contracts
	status := "inativo"

	newID := uuid.New().String()
	createdAt := time.Now()

	// Normalize all optional string fields (empty strings become NULL)
	nickname := normalizeOptionalString(client.Nickname)
	email := normalizeOptionalString(client.Email)
	phone := normalizeOptionalString(client.Phone)
	address := normalizeOptionalString(client.Address)
	notes := normalizeOptionalString(client.Notes)
	tags := normalizeOptionalString(client.Tags)
	contactPreference := normalizeOptionalString(client.ContactPreference)
	documents := normalizeOptionalString(client.Documents)

	sqlStatement := `INSERT INTO clients
		(id, name, registration_id, nickname, birth_date, email, phone, address, notes,
		 status, tags, contact_preference, last_contact_date, next_action_date, created_at, documents)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	_, err = s.db.Exec(sqlStatement,
		newID, trimmedName, formattedID, nickname, client.BirthDate,
		email, phone, address, notes,
		status, tags, contactPreference, client.LastContactDate,
		client.NextActionDate, createdAt, documents)

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
	// Update client status based on active contracts
	if err := s.UpdateClientStatus(newID); err != nil {
		// Non-critical, just log but don't fail
	}

	return newID, nil
}

// GetClientByID retorna um cliente pelo ID
func (s *ClientStore) GetClientByID(id string) (*domain.Client, error) {
	if id == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM clients WHERE id = $1`
	row := s.db.QueryRow(sqlStatement, id)

	var client domain.Client
	err := row.Scan(&client.ID, &client.Name, &client.RegistrationID, &client.Nickname,
		&client.BirthDate, &client.Email, &client.Phone, &client.Address, &client.Notes,
		&client.Status, &client.Tags, &client.ContactPreference, &client.LastContactDate,
		&client.NextActionDate, &client.CreatedAt, &client.Documents, &client.ArchivedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &client, nil
}

// GetClientNameByID returns only the client's name for a given ID.
func (s *ClientStore) GetClientNameByID(id string) (string, error) {
	client, err := s.GetClientByID(id)
	if err != nil {
		return "", err
	}
	if client == nil {
		return "", errors.New("client not found")
	}
	return client.Name, nil
}

// GetClientsByName busca clientes por nome (case-insensitive, parcial)
func (s *ClientStore) GetClientsByName(name string) ([]domain.Client, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM clients WHERE LOWER(name) LIKE LOWER($1) AND archived_at IS NULL`
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
	var clients []domain.Client
	for rows.Next() {
		var client domain.Client
		if err = rows.Scan(&client.ID, &client.Name, &client.RegistrationID, &client.Nickname,
			&client.BirthDate, &client.Email, &client.Phone, &client.Address, &client.Notes,
			&client.Status, &client.Tags, &client.ContactPreference, &client.LastContactDate,
			&client.NextActionDate, &client.CreatedAt, &client.Documents, &client.ArchivedAt); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return clients, nil
}

// UpdateClient atualiza um cliente existente
func (s *ClientStore) UpdateClient(client domain.Client) error {
	if client.ID == "" {
		return errors.New("client ID cannot be empty")
	}

	// Validar cliente usando validações do domínio
	validationErrors := domain.ValidateClient(&client)
	if !validationErrors.IsValid() {
		return errors.New(validationErrors.Error())
	}

	// Status will be auto-calculated, ignore any status from client input

	// Trim and validate name
	trimmedName, err := ValidateName(client.Name, 255)
	if err != nil {
		return err
	}

	// Check if name is already taken by another client (only when registration_id is NULL)
	var count int
	if client.RegistrationID == nil {
		err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE name = $1 AND id != $2 AND registration_id IS NULL", trimmedName, client.ID).Scan(&count)
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
	if client.RegistrationID != nil {
		trimmedRegID := strings.TrimSpace(*client.RegistrationID)
		if trimmedRegID != "" {
			if !isValidCPFOrCNPJ(trimmedRegID) {
				return errors.New("registration ID must be a valid CPF or CNPJ")
			}
			formatted, err := FormatCPFOrCNPJ(trimmedRegID)
			if err != nil {
				return errors.New("registration ID must be a valid CPF or CNPJ")
			}

			// Check for duplicate registration ID (excluding current client)
			err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE registration_id = $1 AND id != $2",
				formatted, client.ID).Scan(&count)
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
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", client.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client does not exist")
	}

	// Default status if empty
	status := client.Status
	if status == "" {
		status = "ativo"
	}

	// Normalize all optional string fields (empty strings become NULL)
	nickname := normalizeOptionalString(client.Nickname)
	email := normalizeOptionalString(client.Email)
	phone := normalizeOptionalString(client.Phone)
	address := normalizeOptionalString(client.Address)
	notes := normalizeOptionalString(client.Notes)
	tags := normalizeOptionalString(client.Tags)
	contactPreference := normalizeOptionalString(client.ContactPreference)
	documents := normalizeOptionalString(client.Documents)

	sqlStatement := `UPDATE clients SET
		name = $1, registration_id = $2, nickname = $3, birth_date = $4,
		email = $5, phone = $6, address = $7, notes = $8,
		status = $9, tags = $10, contact_preference = $11,
		last_contact_date = $12, next_action_date = $13, documents = $14
		WHERE id = $15`

	result, err := s.db.Exec(sqlStatement,
		trimmedName, formattedID, nickname, client.BirthDate,
		email, phone, address, notes,
		status, tags, contactPreference,
		client.LastContactDate, client.NextActionDate, documents,
		client.ID)

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

	// Update client status based on active contracts
	if err := s.UpdateClientStatus(client.ID); err != nil {
		// Non-critical, just log but don't fail
	}

	return nil
}

// UpdateClientStatus atualiza o status do cliente baseado nos contratos ativos
// Ignora clientes arquivados
func (s *ClientStore) UpdateClientStatus(clientID string) error {
	if clientID == "" {
		return errors.New("client ID cannot be empty")
	}

	// Check if client is archived - don't update status for archived clients
	var archivedAt *time.Time
	err := s.db.QueryRow(`SELECT archived_at FROM clients WHERE id = $1`, clientID).Scan(&archivedAt)
	if err != nil {
		return err
	}
	if archivedAt != nil {
		return nil // Don't update status for archived clients
	}

	// Count active contracts (not archived and either no end_date or end_date in future)
	var activeContracts int
	now := time.Now()
	err = s.db.QueryRow(`
		SELECT COUNT(*)
		FROM contracts
		WHERE client_id = $1
		AND archived_at IS NULL
		AND (end_date IS NULL OR end_date > $2)
	`, clientID, now).Scan(&activeContracts)
	if err != nil {
		return err
	}

	// Set status based on active contracts
	var newStatus string
	if activeContracts > 0 {
		newStatus = "ativo"
	} else {
		newStatus = "inativo"
	}

	_, err = s.db.Exec(`UPDATE clients SET status = $1 WHERE id = $2`, newStatus, clientID)
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

// ArchiveClient define a data de arquivamento para a data/hora atual.
// Além disso, arquiva todas as licenças permanentes do cliente (end_date >= 9999-01-01).
func (s *ClientStore) ArchiveClient(id string) error {
	if id == "" {
		return errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}

	// Arquivar cliente
	sqlStatement := `UPDATE clients SET archived_at = $1 WHERE id = $2`
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
		`UPDATE contracts SET archived_at = $1 WHERE client_id = $2 AND archived_at IS NULL`,
		time.Now(), id,
	)
	if err != nil {
		return err
	}

	return nil
}

// UnarchiveClient define a data de arquivamento de volta para NULL.
func (s *ClientStore) UnarchiveClient(id string) error {
	if id == "" {
		return errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}
	sqlStatement := `UPDATE clients SET archived_at = NULL WHERE id = $1`
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
// DeleteClientPermanently remove permanentemente um cliente e seus dados associados.
func (s *ClientStore) DeleteClientPermanently(id string) error {
	if id == "" {
		return errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}
	// NOVA REGRA: Só pode excluir cliente se todos os contratos estiverem expirados ou arquivados
	var blockedContracts int
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM contracts
		WHERE client_id = $1
		AND archived_at IS NULL
		AND end_date > $2
	`, id, time.Now()).Scan(&blockedContracts)
	if err != nil {
		return err
	}
	if blockedContracts > 0 {
		return errors.New("cannot delete client with active or unarchived contracts")
	}
	// Cascade delete: remover dependentes e contratos associados ao cliente
	_, err = s.db.Exec("DELETE FROM contracts WHERE client_id = $1", id)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("DELETE FROM dependents WHERE client_id = $1", id)
	if err != nil {
		return err
	}
	sqlStatement := `DELETE FROM clients WHERE id = $1`
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

// GetAllClients retorna todos os clientes não arquivados
func (s *ClientStore) GetAllClients() (clients []domain.Client, err error) {
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM clients WHERE archived_at IS NULL`

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
		var client domain.Client
		if err = rows.Scan(&client.ID, &client.Name, &client.RegistrationID, &client.Nickname,
			&client.BirthDate, &client.Email, &client.Phone, &client.Address, &client.Notes,
			&client.Status, &client.Tags, &client.ContactPreference, &client.LastContactDate,
			&client.NextActionDate, &client.CreatedAt, &client.Documents, &client.ArchivedAt); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}

// GetArchivedClients retorna todos os clientes arquivados
func (s *ClientStore) GetArchivedClients() (clients []domain.Client, err error) {
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM clients WHERE archived_at IS NOT NULL`

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
		var client domain.Client
		if err = rows.Scan(&client.ID, &client.Name, &client.RegistrationID, &client.Nickname,
			&client.BirthDate, &client.Email, &client.Phone, &client.Address, &client.Notes,
			&client.Status, &client.Tags, &client.ContactPreference, &client.LastContactDate,
			&client.NextActionDate, &client.CreatedAt, &client.Documents, &client.ArchivedAt); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}

// GetAllClientsIncludingArchived retorna todos os clientes, incluindo os arquivados
func (s *ClientStore) GetAllClientsIncludingArchived() (clients []domain.Client, err error) {
	sqlStatement := `SELECT id, name, registration_id, nickname, birth_date, email, phone, address,
		notes, status, tags, contact_preference, last_contact_date, next_action_date,
		created_at, documents, archived_at
		FROM clients`

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
		var client domain.Client
		if err = rows.Scan(&client.ID, &client.Name, &client.RegistrationID, &client.Nickname,
			&client.BirthDate, &client.Email, &client.Phone, &client.Address, &client.Notes,
			&client.Status, &client.Tags, &client.ContactPreference, &client.LastContactDate,
			&client.NextActionDate, &client.CreatedAt, &client.Documents, &client.ArchivedAt); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}
