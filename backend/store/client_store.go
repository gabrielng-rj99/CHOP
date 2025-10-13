// Licenses-Manager/backend/store/client_store.go

package store

import (
	"Licenses-Manager/backend/domain"
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

// CreateClient foi atualizado para incluir a nova coluna (que será NULL por padrão)
func (s *ClientStore) CreateClient(client domain.Client) (string, error) {
	if client.Name == "" {
		return "", errors.New("client name cannot be empty")
	}
	if client.RegistrationID == "" {
		return "", errors.New("client registration ID cannot be empty")
	}
	if !isValidCPFOrCNPJ(client.RegistrationID) {
		return "", errors.New("registration ID must be a valid CPF or CNPJ")
	}
	// Check for duplicate registration ID
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE registration_id = ?", client.RegistrationID).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	if count > 0 {
		return "", errors.New("client registration ID already exists")
	}
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO clients (id, name, registration_id) VALUES (?, ?, ?)`
	_, err = s.db.Exec(sqlStatement, newID, client.Name, client.RegistrationID)
	if err != nil {
		// Handle unique constraint violation for registration ID
		if err.Error() != "" &&
			(strings.Contains(err.Error(), "UNIQUE constraint failed: clients.registration_id") ||
				strings.Contains(err.Error(), "restrição UNIQUE falhou: clients.registration_id")) {
			return "", errors.New("client registration ID already exists")
		}
		return "", err
	}
	return newID, nil
}

// GetClientByID foi atualizado para ler a nova coluna
func (s *ClientStore) GetClientByID(id string) (*domain.Client, error) {
	if id == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, registration_id, archived_at FROM clients WHERE id = ?`
	row := s.db.QueryRow(sqlStatement, id)

	var client domain.Client
	err := row.Scan(&client.ID, &client.Name, &client.RegistrationID, &client.ArchivedAt)
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

// UpdateClient também foi atualizado
func (s *ClientStore) UpdateClient(client domain.Client) error {
	if client.ID == "" {
		return errors.New("client ID cannot be empty")
	}
	if client.Name == "" {
		return errors.New("client name cannot be empty")
	}
	if client.RegistrationID == "" {
		return errors.New("client registration ID cannot be empty")
	}
	if !isValidCPFOrCNPJ(client.RegistrationID) {
		return errors.New("registration ID must be a valid CPF or CNPJ")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", client.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client does not exist")
	}
	sqlStatement := `UPDATE clients SET name = ?, registration_id = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, client.Name, client.RegistrationID, client.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no client updated")
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
func (s *ClientStore) ArchiveClient(id string) error {
	if id == "" {
		return errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}
	sqlStatement := `UPDATE clients SET archived_at = ? WHERE id = ?`
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
	return nil
}

// UnarchiveClient define a data de arquivamento de volta para NULL.
func (s *ClientStore) UnarchiveClient(id string) error {
	if id == "" {
		return errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}
	sqlStatement := `UPDATE clients SET archived_at = NULL WHERE id = ?`
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
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("client not found")
	}
	sqlStatement := `DELETE FROM clients WHERE id = ?`
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
	sqlStatement := `SELECT id, name, registration_id, archived_at FROM clients WHERE archived_at IS NOT NULL`

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
		if err = rows.Scan(&client.ID, &client.Name, &client.RegistrationID, &client.ArchivedAt); err != nil {
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
	sqlStatement := `SELECT id, name, cnpj, archived_at FROM clients WHERE archived_at IS NOT NULL`

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

	clients = []domain.Client{}
	for rows.Next() {
		var client domain.Client
		if err = rows.Scan(&client.ID, &client.Name, &client.RegistrationID, &client.ArchivedAt); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}
