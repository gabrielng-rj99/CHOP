// Contracts-Manager/backend/store/contract_store.go

package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"Contracts-Manager/backend/domain" // Use o nome do seu módulo

	"github.com/google/uuid"
)

// ContractStore é a nossa "caixa de ferramentas" para operações com a tabela contracts.
type ContractStore struct {
	db DBInterface
}

// NewContractStore cria uma nova instância de ContractStore.
func NewContractStore(db DBInterface) *ContractStore {
	return &ContractStore{
		db: db,
	}
}

// CreateContract insere um novo contrato no banco de dados.
func (s *ContractStore) CreateContract(contract domain.Contract) (string, error) {
	// Model and ProductKey are now optional
	var trimmedModel, trimmedProductKey string
	var err error
	if contract.Model != "" {
		trimmedModel, err = ValidateName(contract.Model, 255)
		if err != nil {
			return "", err
		}
	}
	if contract.ProductKey != "" {
		trimmedProductKey, err = ValidateName(contract.ProductKey, 255)
		if err != nil {
			return "", err
		}
	}

	// Start and End dates are now optional - only validate if both are provided
	if !contract.StartDate.IsZero() && !contract.EndDate.IsZero() {
		if contract.EndDate.Before(contract.StartDate) || contract.EndDate.Equal(contract.StartDate) {
			return "", errors.New("end date must be after start date")
		}
	}

	if contract.LineID == "" {
		return "", errors.New("line ID cannot be empty")
	}
	if contract.ClientID == "" {
		return "", errors.New("client ID cannot be empty")
	}

	// Check if line exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = $1", contract.LineID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", errors.New("line does not exist")
	}

	// Check if client exists e não está arquivado
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1 AND archived_at IS NULL", contract.ClientID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", errors.New("client does not exist or is archived")
	}

	// If dependentID is provided, check if dependent exists and belongs to the client
	if contract.DependentID != nil && *contract.DependentID != "" {
		err = s.db.QueryRow("SELECT COUNT(*) FROM dependents WHERE id = $1 AND client_id = $2", *contract.DependentID, contract.ClientID).Scan(&count)
		if err != nil {
			return "", err
		}
		if count == 0 {
			return "", errors.New("dependent does not exist or does not belong to the specified client")
		}
	}

	// Check for duplicate product key only if provided
	if contract.ProductKey != "" {
		err = s.db.QueryRow("SELECT COUNT(*) FROM contracts WHERE product_key = $1", contract.ProductKey).Scan(&count)
		if err != nil {
			return "", err
		}
		if count > 0 {
			return "", errors.New("product key already exists")
		}
	}

	// NOVA REGRA: Verificar sobreposição temporal apenas se ambas as datas forem fornecidas
	if !contract.StartDate.IsZero() && !contract.EndDate.IsZero() {
		var overlapCount int
		if contract.DependentID != nil && *contract.DependentID != "" {
			err = s.db.QueryRow(`
				SELECT COUNT(*) FROM contracts
				WHERE line_id = $1 AND client_id = $2 AND dependent_id = $3
				AND start_date IS NOT NULL AND end_date IS NOT NULL
				AND (
					(start_date <= $4 AND end_date >= $5) OR
					(start_date <= $6 AND end_date >= $7)
				)
			`, contract.LineID, contract.ClientID, *contract.DependentID,
				contract.EndDate, contract.EndDate,
				contract.StartDate, contract.StartDate,
			).Scan(&overlapCount)
		} else {
			err = s.db.QueryRow(`
				SELECT COUNT(*) FROM contracts
				WHERE line_id = $1 AND client_id = $2 AND dependent_id IS NULL
				AND start_date IS NOT NULL AND end_date IS NOT NULL
				AND (
					(start_date <= $3 AND end_date >= $4) OR
					(start_date <= $5 AND end_date >= $6)
				)
			`, contract.LineID, contract.ClientID,
				contract.EndDate, contract.EndDate,
				contract.StartDate, contract.StartDate,
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
		INSERT INTO contracts (id, model, product_key, start_date, end_date, line_id, client_id, dependent_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = s.db.Exec(sqlStatement,
		newID,
		trimmedModel,
		trimmedProductKey,
		nullTimeFromTime(contract.StartDate),
		nullTimeFromTime(contract.EndDate),
		contract.LineID,
		contract.ClientID,
		contract.DependentID,
	)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// Helper function to convert time.Time to sql.NullTime
func nullTimeFromTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: t, Valid: true}
}

// GetContractsByClientID fetches all contracts for a specific client.
func (s *ContractStore) GetContractsByClientID(clientID string) (contracts []domain.Contract, err error) {
	if clientID == "" {
		return nil, errors.New("client ID is required")
	}
	// Check if client exists and is not archived
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1 AND archived_at IS NULL", clientID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("client not found or archived")
	}

	sqlStatement := `SELECT id, model, product_key, start_date, end_date, line_id, client_id, dependent_id FROM contracts WHERE client_id = $1`
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

	contracts = []domain.Contract{}
	for rows.Next() {
		var c domain.Contract
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ProductKey, &startDate, &endDate, &c.LineID, &c.ClientID, &c.DependentID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			c.StartDate = startDate.Time
		}
		if endDate.Valid {
			c.EndDate = endDate.Time
		}
		contracts = append(contracts, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return contracts, nil
}

// GetContractsExpiringSoon busca contratos que expiram nos próximos 'days' dias.
func (s *ContractStore) GetContractsExpiringSoon(days int) (contracts []domain.Contract, err error) {
	now := time.Now()
	limitDate := now.AddDate(0, 0, days)

	sqlStatement := `SELECT id, model, product_key, start_date, end_date, line_id, client_id, dependent_id
	                 FROM contracts
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

	contracts = []domain.Contract{}
	for rows.Next() {
		var c domain.Contract
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ProductKey, &startDate, &endDate, &c.LineID, &c.ClientID, &c.DependentID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			c.StartDate = startDate.Time
		}
		if endDate.Valid {
			c.EndDate = endDate.Time
		}
		contracts = append(contracts, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return contracts, nil
}

// GetContractsNotStarted busca contratos que ainda não iniciaram (start_date no futuro)
func (s *ContractStore) GetContractsNotStarted() (contracts []domain.Contract, err error) {
	now := time.Now()

	sqlStatement := `SELECT id, model, product_key, start_date, end_date, line_id, client_id, dependent_id
	                 FROM contracts
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

	contracts = []domain.Contract{}
	for rows.Next() {
		var c domain.Contract
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ProductKey, &startDate, &endDate, &c.LineID, &c.ClientID, &c.DependentID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			c.StartDate = startDate.Time
		}
		if endDate.Valid {
			c.EndDate = endDate.Time
		}
		contracts = append(contracts, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return contracts, nil
}

func (s *ContractStore) UpdateContract(contract domain.Contract) error {
	if contract.ID == "" {
		return errors.New("contract ID cannot be empty")
	}

	// Model and ProductKey are now optional
	var trimmedModel, trimmedProductKey string
	var err error
	if contract.Model != "" {
		trimmedModel, err = ValidateName(contract.Model, 255)
		if err != nil {
			return err
		}
	}
	if contract.ProductKey != "" {
		trimmedProductKey, err = ValidateName(contract.ProductKey, 255)
		if err != nil {
			return err
		}
	}

	// Datas são opcionais, mas se ambas forem fornecidas, end_date deve ser maior que start_date
	if !contract.StartDate.IsZero() && !contract.EndDate.IsZero() {
		if contract.EndDate.Before(contract.StartDate) || contract.EndDate.Equal(contract.StartDate) {
			return errors.New("end date must be after start date")
		}
	}

	// If dependentID is provided, check if dependent exists and belongs to the client
	if contract.DependentID != nil && *contract.DependentID != "" {
		var depCount int
		err = s.db.QueryRow("SELECT COUNT(*) FROM dependents WHERE id = $1 AND client_id = $2", *contract.DependentID, contract.ClientID).Scan(&depCount)
		if err != nil {
			return err
		}
		if depCount == 0 {
			return errors.New("dependent does not exist or does not belong to the specified client")
		}
	}

	// Check if contract exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM contracts WHERE id = $1", contract.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("contract does not exist")
	}

	sqlStatement := `UPDATE contracts SET model = $1, product_key = $2, start_date = $3, end_date = $4 WHERE id = $5`
	result, err := s.db.Exec(sqlStatement, trimmedModel, trimmedProductKey,
		nullTimeFromTime(contract.StartDate),
		nullTimeFromTime(contract.EndDate),
		contract.ID)
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

// GetContractByID busca um contrato específico pelo seu ID
func (s *ContractStore) GetContractByID(id string) (*domain.Contract, error) {
	if id == "" {
		return nil, errors.New("contract ID cannot be empty")
	}
	sqlStatement := `
		SELECT id, model, product_key, start_date, end_date, line_id, client_id, dependent_id
		FROM contracts
		WHERE id = $1`

	var contract domain.Contract
	var startDate, endDate sql.NullTime
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&contract.ID,
		&contract.Model,
		&contract.ProductKey,
		&startDate,
		&endDate,
		&contract.LineID,
		&contract.ClientID,
		&contract.DependentID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if startDate.Valid {
		contract.StartDate = startDate.Time
	}
	if endDate.Valid {
		contract.EndDate = endDate.Time
	}

	return &contract, nil
}

// Utility: Get explicit status for a contract (ativo, expirando, expirado)
// Uses time.Now() internally, so timing can matter in tests
func GetContractStatus(contract domain.Contract) string {
	now := time.Now()

	if contract.EndDate.IsZero() {
		return "ativo" // Contratos sem data de término são considerados ativos
	}

	if contract.EndDate.Before(now) {
		return "expirado"
	}

	// Contract is expiring if it expires within 30 days
	daysUntilExpiry := contract.EndDate.Sub(now).Hours() / 24
	if daysUntilExpiry > 0 && daysUntilExpiry <= 30 {
		return "expirando"
	}
	return "ativo"
}

func (s *ContractStore) DeleteContract(id string) error {
	if id == "" {
		return errors.New("contract ID cannot be empty")
	}
	// Check if contract exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM contracts WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("contract does not exist")
	}
	sqlStatement := `DELETE FROM contracts WHERE id = $1`
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

// GetAllContracts fetches all contracts in the system (excluding archived)
func (s *ContractStore) GetAllContracts() (contracts []domain.Contract, err error) {
	sqlStatement := `SELECT id, model, product_key, start_date, end_date, line_id, client_id, dependent_id
	                 FROM contracts WHERE archived_at IS NULL`
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

	contracts = []domain.Contract{}
	for rows.Next() {
		var c domain.Contract
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ProductKey, &startDate, &endDate, &c.LineID, &c.ClientID, &c.DependentID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			c.StartDate = startDate.Time
		}
		if endDate.Valid {
			c.EndDate = endDate.Time
		}
		contracts = append(contracts, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return contracts, nil
}

// GetContractsByName fetches contracts by partial name/model (case-insensitive)
func (s *ContractStore) GetContractsByName(name string) ([]domain.Contract, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	// Busca case-insensitive já funcionará com CITEXT
	sqlStatement := `SELECT id, model, product_key, start_date, end_date, line_id, client_id, dependent_id
	                 FROM contracts WHERE model LIKE $1`
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
	var contracts []domain.Contract
	for rows.Next() {
		var c domain.Contract
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ProductKey, &startDate, &endDate, &c.LineID, &c.ClientID, &c.DependentID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			c.StartDate = startDate.Time
		}
		if endDate.Valid {
			c.EndDate = endDate.Time
		}
		contracts = append(contracts, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return contracts, nil
}

// GetContractsByLineID fetches all contracts for a specific line
func (s *ContractStore) GetContractsByLineID(lineID string) (contracts []domain.Contract, err error) {
	if lineID == "" {
		return nil, errors.New("line ID is required")
	}
	// Check if line exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = $1", lineID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("line not found")
	}

	sqlStatement := `SELECT id, model, product_key, start_date, end_date, line_id, client_id, dependent_id
	                 FROM contracts WHERE line_id = $1`
	rows, err := s.db.Query(sqlStatement, lineID)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	contracts = []domain.Contract{}
	for rows.Next() {
		var c domain.Contract
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ProductKey, &startDate, &endDate, &c.LineID, &c.ClientID, &c.DependentID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			c.StartDate = startDate.Time
		}
		if endDate.Valid {
			c.EndDate = endDate.Time
		}
		contracts = append(contracts, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return contracts, nil
}

// GetContractsByCategoryID fetches all contracts for a specific category
func (s *ContractStore) GetContractsByCategoryID(categoryID string) (contracts []domain.Contract, err error) {
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
		SELECT c.id, c.model, c.product_key, c.start_date, c.end_date, c.line_id, c.client_id, c.dependent_id
		FROM contracts c
		INNER JOIN lines ln ON c.line_id = ln.id
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

	contracts = []domain.Contract{}
	for rows.Next() {
		var c domain.Contract
		var startDate, endDate sql.NullTime
		if err = rows.Scan(&c.ID, &c.Model, &c.ProductKey, &startDate, &endDate, &c.LineID, &c.ClientID, &c.DependentID); err != nil {
			return nil, err
		}
		if startDate.Valid {
			c.StartDate = startDate.Time
		}
		if endDate.Valid {
			c.EndDate = endDate.Time
		}
		contracts = append(contracts, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return contracts, nil
}
