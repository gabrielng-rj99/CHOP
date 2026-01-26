package store

import (
	"database/sql"
	"time"

	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/repository"
	auditstore "Open-Generic-Hub/backend/repository/audit"
	categorystore "Open-Generic-Hub/backend/repository/category"
	clientstore "Open-Generic-Hub/backend/repository/client"
	contractstore "Open-Generic-Hub/backend/repository/contract"
	rolestore "Open-Generic-Hub/backend/repository/role"
	settingsstore "Open-Generic-Hub/backend/repository/settings"
	userstore "Open-Generic-Hub/backend/repository/user"
)

// DBInterface re-export
type DBInterface = repository.DBInterface

// DBWithTx re-export for stores that need transaction support
type DBWithTx = repository.DBWithTx

// Domain types re-export
type User = domain.User
type Affiliate = domain.Affiliate
type Client = domain.Client
type Contract = domain.Contract
type Category = domain.Category
type Subcategory = domain.Subcategory

// Store types re-export
type UserStore = userstore.UserStore
type UserThemeStore = userstore.UserThemeStore
type ClientStore = clientstore.ClientStore
type AffiliateStore = clientstore.AffiliateStore
type ContractStore = contractstore.ContractStore
type FinancialStore = contractstore.FinancialStore
type CategoryStore = categorystore.CategoryStore
type SubcategoryStore = categorystore.SubcategoryStore
type RoleStore = rolestore.RoleStore
type AuditStore = auditstore.AuditStore
type SettingsStore = settingsstore.SettingsStore

// Request/response types re-export
type AuditLogRequest = auditstore.AuditLogRequest
type AuditLogFilter = auditstore.AuditLogFilter
type UserThemeSettings = userstore.UserThemeSettings
type Role = rolestore.Role
type Permission = rolestore.Permission
type RoleWithPermissions = rolestore.RoleWithPermissions
type UserPermissions = rolestore.UserPermissions
type SystemSetting = settingsstore.SystemSetting

// Constructors re-export
func NewUserStore(db DBInterface) *UserStore {
	return userstore.NewUserStore(db)
}

func NewUserThemeStore(db DBInterface) *UserThemeStore {
	return userstore.NewUserThemeStore(db)
}

func NewClientStore(db DBInterface) *ClientStore {
	return clientstore.NewClientStore(db)
}

func NewAffiliateStore(db DBInterface) *AffiliateStore {
	return clientstore.NewAffiliateStore(db)
}

func NewContractStore(db DBInterface) *ContractStore {
	return contractstore.NewContractStore(db)
}

// NewFinancialStore requires DBWithTx because it uses transactions
func NewFinancialStore(db DBWithTx) *FinancialStore {
	return contractstore.NewFinancialStore(db)
}

func NewCategoryStore(db DBInterface) *CategoryStore {
	return categorystore.NewCategoryStore(db)
}

func NewSubcategoryStore(db DBInterface) *SubcategoryStore {
	return categorystore.NewSubcategoryStore(db)
}

// NewRoleStore requires DBWithTx because it uses transactions
func NewRoleStore(db DBWithTx) *RoleStore {
	return rolestore.NewRoleStore(db)
}

func NewAuditStore(db DBInterface) *AuditStore {
	return auditstore.NewAuditStore(db)
}

func NewSettingsStore(db DBInterface) *SettingsStore {
	return settingsstore.NewSettingsStore(db)
}

// Validation functions re-export
func ValidateName(name string, maxLength int) (string, error) {
	return repository.ValidateName(name, maxLength)
}
func ValidateUsername(username string) error {
	return repository.ValidateUsername(username)
}
func ValidateStrongPassword(password string, minLength int) error {
	return userstore.ValidateStrongPassword(password, minLength)
}
func GetMinPasswordLengthForRole(role string) int {
	return userstore.GetMinPasswordLengthForRole(role)
}
func HashPassword(password string) (string, error) {
	return userstore.HashPassword(password)
}
func ValidateCPF(cpf string) bool {
	return repository.ValidateCPF(cpf)
}
func ValidateCNPJ(cnpj string) bool {
	return repository.ValidateCNPJ(cnpj)
}
func ValidateCPFOrCNPJ(id string) bool {
	return repository.ValidateCPFOrCNPJ(id)
}
func FormatCPFOrCNPJ(id string) (string, error) {
	return repository.FormatCPFOrCNPJ(id)
}

// Test helpers re-export
func SetupTestDB() (*sql.DB, error) {
	return repository.SetupTestDB()
}
func CloseDB(db *sql.DB) error {
	return repository.CloseDB(db)
}
func ClearTables(db *sql.DB) error {
	return repository.ClearTables(db)
}
func InsertTestClient(db *sql.DB, name, registrationID string) (string, error) {
	return repository.InsertTestClient(db, name, registrationID)
}
func InsertTestAffiliate(db *sql.DB, name string, clientID string) (string, error) {
	return repository.InsertTestAffiliate(db, name, clientID)
}
func InsertTestCategory(db *sql.DB, name string) (string, error) {
	return repository.InsertTestCategory(db, name)
}
func InsertTestSubcategory(db *sql.DB, name string, categoryID string) (string, error) {
	return repository.InsertTestSubcategory(db, name, categoryID)
}
func InsertTestContract(db *sql.DB, model, itemKey string, startDate, endDate *time.Time, subcategoryID, clientID string, subClientID interface{}) (string, error) {
	return repository.InsertTestContract(db, model, itemKey, startDate, endDate, subcategoryID, clientID, subClientID)
}

// Errors re-export
var (
	ErrClientNotFound           = repository.ErrClientNotFound
	ErrClientHasActiveLicenses  = repository.ErrClientHasActiveLicenses
	ErrDuplicatedRegistrationID = repository.ErrDuplicatedRegistrationID
	ErrInvalidClientClient      = repository.ErrInvalidClientClient
	ErrLineNotFound             = repository.ErrLineNotFound
	ErrLicenseNotFound          = repository.ErrLicenseNotFound
	ErrLicenseOverlap           = repository.ErrLicenseOverlap
	ErrArchivedClient           = repository.ErrArchivedClient
	ErrNoRows                   = repository.ErrNoRows
)

// ValidationError type
type ValidationError = repository.ValidationError

// NewValidationError creates a new validation error
func NewValidationError(message string, err error) *ValidationError {
	return repository.NewValidationError(message, err)
}

// IsValidationError checks if an error is a ValidationError
func IsValidationError(err error) bool {
	return repository.IsValidationError(err)
}
