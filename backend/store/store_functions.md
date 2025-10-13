# Store Package Documentation

## Overview

The store package provides database operations for the License Management System, handling all CRUD operations and business logic for entities like clients, licenses, categories, and entities.

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

#### ClientStore

Manages client-related database operations.

**Methods:**
- `NewClientStore(db DBInterface) *ClientStore`
  - Creates new store instance

- `CreateClient(client domain.Client) (string, error)`
  - Creates new client record
  - Validates: name and registration_id not empty
  - Returns: UUID of created client

- `GetClientByID(id string) (*domain.Client, error)`
  - Retrieves single client by ID
  - Returns nil if not found

- `UpdateClient(client domain.Client) error`
  - Updates existing client details

- `ArchiveClient(id string) error`
  - Archives client (soft delete)

- `UnarchiveClient(id string) error`
  - Restores archived client

- `DeleteClientPermanently(id string) error`
  - Hard deletes client and related data

- `GetAllClients() ([]domain.Client, error)`
  - Lists all non-archived clients

- `GetArchivedClients() ([]domain.Client, error)`
  - Lists all archived clients

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
  - Deletes category if no lines reference it

#### LineStore

Manages license lines within categories.

**Methods:**
- `NewLineStore(db DBInterface) *LineStore`
  - Creates new store instance

- `CreateLine(licensetype domain.Line) (string, error)`
  - Creates new license line
  - Validates: name and categoryID not empty

- `GetLinesByCategoryID(categoryID string) ([]domain.Line, error)`
  - Lists lines in specific category

- `GetLineByID(id string) (*domain.Line, error)`
  - Retrieves single line
  - Returns nil if not found

- `GetAllLines() ([]domain.Line, error)`
  - Lists all license lines

- `UpdateLine(licensetype domain.Line) error`
  - Updates type details

- `DeleteLine(id string) error`
  - Deletes type if no licenses reference it

#### EntityStore

Manages client entities/branches.

**Methods:**
- `NewEntityStore(db DBInterface) *EntityStore`
  - Creates new store instance

- `CreateEntity(entity domain.Entity) (string, error)`
  - Creates new entity
  - Validates: name and clientID not empty

- `GetEntitiesByClientID(clientID string) ([]domain.Entity, error)`
  - Lists entities belonging to client

- `UpdateEntity(entity domain.Entity) error`
  - Updates entity details

- `DeleteEntity(id string) error`
  - Deletes entity if no licenses reference it

- `GetEntityByID(id string) (*domain.Entity, error)`
  - Retrieves single entity
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
    - Line ID exists
    - Client ID exists
    - End date after start date

- `GetLicensesByClientID(clientID string) ([]domain.License, error)`
  - Lists client's active licenses
  - Excludes archived clients

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
  - Checks if error is validation line

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
