# Store Package Documentation

## Overview

The store package provides database operations for the License Management System, handling all CRUD operations and business logic for entities like companies, licenses, categories, and units.

## Components

### Interfaces

#### DBInterface
Main database interface used throughout the package.

```go
type DBInterface interface {
    Query(query string, args ...interface{}) (*sql.Rows, error)
    QueryRow(query string, args ...interface{}) *sql.Row
    Exec(query string, args ...interface{}) (sql.Result, error)
    Close() error
}
```

Provides abstraction for database operations, allowing both real database connections and mocks for testing.

### Stores

#### CompanyStore

Manages company-related database operations.

**Methods:**
- `NewCompanyStore(db DBInterface) *CompanyStore`
  - Creates new store instance
  
- `CreateCompany(company domain.Company) (string, error)`
  - Creates new company record
  - Validates: name and CNPJ not empty
  - Returns: UUID of created company
  
- `GetCompanyByID(id string) (*domain.Company, error)`
  - Retrieves single company by ID
  - Returns nil if not found
  
- `UpdateCompany(company domain.Company) error`
  - Updates existing company details
  
- `ArchiveCompany(id string) error`
  - Archives company (soft delete)
  
- `UnarchiveCompany(id string) error`
  - Restores archived company
  
- `DeleteCompanyPermanently(id string) error` 
  - Hard deletes company and related data
  
- `GetAllCompanies() ([]domain.Company, error)`
  - Lists all non-archived companies
  
- `GetArchivedCompanies() ([]domain.Company, error)`
  - Lists all archived companies

#### CategoryStore

Manages license categories.

**Methods:**
- `NewCategoryStore(db DBInterface) *CategoryStore`
  - Creates new store instance
  
- `CreateCategory(category domain.Category) (string, error)` 
  - Creates new category
  - Validates: name not empty
  - Returns: UUID of created category
  
- `GetAllCategories() ([]domain.Category, error)`
  - Lists all categories
  
- `GetCategoryByID(id string) (*domain.Category, error)`
  - Retrieves single category
  - Returns nil if not found
  
- `UpdateCategory(category domain.Category) error`
  - Updates category details
  
- `DeleteCategory(id string) error`
  - Deletes category if no types reference it

#### TypeStore 

Manages license types within categories.

**Methods:**
- `NewTypeStore(db DBInterface) *TypeStore`
  - Creates new store instance
  
- `CreateType(licensetype domain.Type) (string, error)`
  - Creates new license type
  - Validates: name and categoryID not empty
  
- `GetTypesByCategoryID(categoryID string) ([]domain.Type, error)`
  - Lists types in specific category
  
- `GetTypeByID(id string) (*domain.Type, error)`
  - Retrieves single type
  - Returns nil if not found
  
- `GetAllTypes() ([]domain.Type, error)`
  - Lists all license types
  
- `UpdateType(licensetype domain.Type) error`
  - Updates type details
  
- `DeleteType(id string) error`
  - Deletes type if no licenses reference it

#### UnitStore

Manages company units/branches.

**Methods:**
- `NewUnitStore(db DBInterface) *UnitStore`
  - Creates new store instance
  
- `CreateUnit(unit domain.Unit) (string, error)`
  - Creates new unit
  - Validates: name and companyID not empty
  
- `GetUnitsByCompanyID(companyID string) ([]domain.Unit, error)`
  - Lists units belonging to company
  
- `UpdateUnit(unit domain.Unit) error`
  - Updates unit details
  
- `DeleteUnit(id string) error`
  - Deletes unit if no licenses reference it
  
- `GetUnitByID(id string) (*domain.Unit, error)`
  - Retrieves single unit
  - Returns nil if not found

#### LicenseStore

Manages software licenses.

**Methods:**
- `NewLicenseStore(db DBInterface) *LicenseStore`
  - Creates new store instance
  
- `CreateLicense(license domain.License) (string, error)`
  - Creates new license
  - Validates:
    - Name not empty
    - Product key not empty
    - Type ID exists
    - Company ID exists
    - End date after start date
  
- `GetLicensesByCompanyID(companyID string) ([]domain.License, error)`
  - Lists company's active licenses
  - Excludes archived companies
  
- `GetLicensesExpiringSoon(days int) ([]domain.License, error)`
  - Lists licenses expiring within days
  
- `UpdateLicense(license domain.License) error`
  - Updates license details
  
- `GetLicenseByID(id string) (*domain.License, error)`
  - Retrieves single license
  - Returns nil if not found
  
- `DeleteLicense(id string) error`
  - Deletes license record

### Error Handling

#### ValidationError

Custom error type for validation failures.

**Methods:**
- `NewValidationError(message string) *ValidationError`
  - Creates validation error with message
  
- `Error() string`
  - Returns error message
  
- `IsValidationError(err error) bool`
  - Checks if error is validation type

**Common Error Cases:**
1. Not Found: Returns `sql.ErrNoRows`
2. Validation: Returns `ValidationError`
3. Database Errors: Returns underlying error
4. Foreign Key: Returns constraint violation

### Best Practices

1. Always check return values for errors
2. Use transaction for multiple operations
3. Close result sets in deferred functions
4. Validate inputs before database operations
5. Handle not found cases appropriately
6. Use prepared statements for security