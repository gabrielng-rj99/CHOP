// Licenses-Manager/backend/store/license_store.go

package store

import (
	"database/sql"
	"errors"
	"time"

	"Licenses-Manager/backend/domain" // Use o nome do seu módulo

	"github.com/google/uuid"
)

// LicenseStore é a nossa "caixa de ferramentas" para operações com a tabela licenses.
type LicenseStore struct {
	db DBInterface
}

// NewLicenseStore cria uma nova instância de LicenseStore.
func NewLicenseStore(db DBInterface) *LicenseStore {
	return &LicenseStore{
		db: db,
	}
}

// CreateLicense insere uma nova licença no banco de dados.
func (s *LicenseStore) CreateLicense(license domain.License) (string, error) {
	if license.Model == "" {
		return "", sql.ErrNoRows // Or use errors.New("license model cannot be empty")
	}
	if license.ProductKey == "" {
		return "", sql.ErrNoRows // Or use errors.New("product key cannot be empty")
	}
	if license.StartDate.IsZero() || license.EndDate.IsZero() {
		return "", sql.ErrNoRows // Or use errors.New("start and end date must be set")
	}
	if license.EndDate.Before(license.StartDate) {
		return "", sql.ErrNoRows // Or use errors.New("end date must be after start date")
	}
	if license.LineID == "" {
		return "", sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	if license.ClientID == "" {
		return "", sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if type exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = ?", license.LineID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("type does not exist")
	}
	// Check if client exists e não está arquivado
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ? AND archived_at IS NULL", license.ClientID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", errors.New("client does not exist or is archived")
	}
	// If entityID is provided, check if entity exists
	if license.EntityID != nil && *license.EntityID != "" {
		err = s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = ?", *license.EntityID).Scan(&count)
		if err != nil {
			return "", err
		}
		if count == 0 {
			return "", sql.ErrNoRows // Or use errors.New("entity does not exist")
		}
	}
	// Check for duplicate product key
	err = s.db.QueryRow("SELECT COUNT(*) FROM licenses WHERE product_key = ?", license.ProductKey).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", sql.ErrNoRows // Or use errors.New("product key already exists")
	}

	// NOVA REGRA: Verificar sobreposição temporal de licenças do mesmo tipo para empresa/unidade
	var overlapCount int
	if license.EntityID != nil && *license.EntityID != "" {
		err = s.db.QueryRow(`
			SELECT COUNT(*) FROM licenses
			WHERE line_id = ? AND client_id = ? AND entity_id = ? AND (
				(start_date <= ? AND end_date >= ?) OR
				(start_date <= ? AND end_date >= ?)
			)
		`, license.LineID, license.ClientID, *license.EntityID,
			license.EndDate, license.EndDate,
			license.StartDate, license.StartDate,
		).Scan(&overlapCount)
	} else {
		err = s.db.QueryRow(`
			SELECT COUNT(*) FROM licenses
			WHERE line_id = ? AND client_id = ? AND entity_id IS NULL AND (
				(start_date <= ? AND end_date >= ?) OR
				(start_date <= ? AND end_date >= ?)
			)
		`, license.LineID, license.ClientID,
			license.EndDate, license.EndDate,
			license.StartDate, license.StartDate,
		).Scan(&overlapCount)
	}
	if err != nil {
		return "", err
	}
	if overlapCount > 0 {
		return "", errors.New("license period overlaps with another license of the same type for this company/unit")
	}

	newID := uuid.New().String()
	sqlStatement := `
		INSERT INTO licenses (id, name, product_key, start_date, end_date, line_id, client_id, entity_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.Exec(sqlStatement,
		newID,
		license.Model, // Model mapeia para name no banco
		license.ProductKey,
		license.StartDate,
		license.EndDate,
		license.LineID,
		license.ClientID,
		license.EntityID, // O driver Go trata o ponteiro *string nil como NULL no banco
	)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetLicensesByClientID fetches all licenses for a specific client.
func (s *LicenseStore) GetLicensesByClientID(clientID string) (licenses []domain.License, err error) {
	if clientID == "" {
		return nil, errors.New("client ID is required")
	}
	// Check if client exists and is not archived
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ? AND archived_at IS NULL", clientID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("client not found or archived")
	}
	// ... rest of the function ...
	sqlStatement := `SELECT id, name, product_key, start_date, end_date, line_id, client_id, entity_id FROM licenses WHERE client_id = ?`
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

	licenses = []domain.License{}
	for rows.Next() {
		var l domain.License
		// Note o &l.EntityID para o campo que pode ser nulo
		if err = rows.Scan(&l.ID, &l.Model, &l.ProductKey, &l.StartDate, &l.EndDate, &l.LineID, &l.ClientID, &l.EntityID); err != nil {
			return nil, err
		}
		licenses = append(licenses, l)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return licenses, nil
}

// GetLicensesExpiringSoon busca licenças que expiram nos próximos 'days' dias.
func (s *LicenseStore) GetLicensesExpiringSoon(days int) (licenses []domain.License, err error) {
	now := time.Now()
	limitDate := now.AddDate(0, 0, days) // Adiciona 'days' dias à data atual

	sqlStatement := `SELECT id, name, product_key, start_date, end_date, line_id, client_id, entity_id FROM licenses WHERE end_date BETWEEN ? AND ?`

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

	licenses = []domain.License{}
	for rows.Next() {
		var l domain.License
		if err = rows.Scan(&l.ID, &l.Model, &l.ProductKey, &l.StartDate, &l.EndDate, &l.LineID, &l.ClientID, &l.EntityID); err != nil {
			return nil, err
		}
		licenses = append(licenses, l)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return licenses, nil
}

func (s *LicenseStore) UpdateLicense(license domain.License) error {
	if license.ID == "" {
		return sql.ErrNoRows // Or use errors.New("license ID cannot be empty")
	}
	if license.Model == "" {
		return sql.ErrNoRows // Or use errors.New("license model cannot be empty")
	}
	if license.ProductKey == "" {
		return sql.ErrNoRows // Or use errors.New("product key cannot be empty")
	}
	if license.StartDate.IsZero() || license.EndDate.IsZero() {
		return sql.ErrNoRows // Or use errors.New("start and end date must be set")
	}
	if license.EndDate.Before(license.StartDate) {
		return sql.ErrNoRows // Or use errors.New("end date must be after start date")
	}
	if license.StartDate.After(license.EndDate) {
		return sql.ErrNoRows // Or use errors.New("start date cannot be after end date")
	}
	// Check if license exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM licenses WHERE id = ?", license.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("license does not exist")
	}
	sqlStatement := `UPDATE licenses SET name = ?, product_key = ?, start_date = ?, end_date = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, license.Model, license.ProductKey, license.StartDate, license.EndDate, license.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows // Or use errors.New("no license updated")
	}
	return nil
}

// GetLicenseByID busca uma licença específica pelo seu ID
func (s *LicenseStore) GetLicenseByID(id string) (*domain.License, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("license ID cannot be empty")
	}
	sqlStatement := `
		SELECT id, name, product_key, start_date, end_date, line_id, client_id, entity_id
		FROM licenses
		WHERE id = ?`

	var license domain.License
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&license.ID,
		&license.Model, // Model mapeia para name no banco
		&license.ProductKey,
		&license.StartDate,
		&license.EndDate,
		&license.LineID,
		&license.ClientID,
		&license.EntityID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &license, nil
}

// Utility: Get explicit status for a license (ativa, expirando, expirada)
func GetLicenseStatus(license domain.License) string {
	now := time.Now()
	expiringSoon := now.AddDate(0, 0, 30) // 30 days window for "expiring"
	if license.EndDate.Before(now) {
		return "expirada"
	}
	if license.EndDate.Before(expiringSoon) {
		return "expirando"
	}
	return "ativa"
}

func (s *LicenseStore) DeleteLicense(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("license ID cannot be empty")
	}
	// Check if license exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM licenses WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("license does not exist")
	}
	sqlStatement := `DELETE FROM licenses WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows // Or use errors.New("no license deleted")
	}
	return nil
}
