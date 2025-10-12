# Store Package Reference

## Overview

The store package implements database operations and business rules for the License Management System. This document details all operations, constraints, validations, and relationships between entities.

## Database Relationships & Constraints

### Companies
- Primary entity that owns licenses and units
- Each company must have:
  - Unique CNPJ
  - Non-empty name
  - Creation date (auto-generated)
- Optional archived_at timestamp for soft deletion
- **Cascade Effects**:
  - Deleting a company will delete all its:
    - Units
    - Licenses
    - Related data

### Units (Company Branches)
- Represents physical locations or departments
- **Required Relationships**:
  - Must belong to an existing company (foreign key: company_id)
- **Constraints**:
  - Cannot exist without a company
  - Must have a non-empty name
  - Name should be unique within the same company
- **Cascade Effects**:
  - When a unit is deleted:
    - Associated licenses are updated to remove unit reference (unit_id set to NULL)
    - Does not affect parent company

### Categories
- Classifies license types
- **Constraints**:
  - Must have unique name
  - Cannot be deleted if has types associated
- **Validations**:
  - Name cannot be empty
  - Name must be unique (case-insensitive)

### Types
- Defines specific license types within categories
- **Required Relationships**:
  - Must belong to a category (foreign key: category_id)
- **Constraints**:
  - Cannot exist without a category
  - Name must be unique within category
  - Cannot be deleted if has licenses associated
- **Validations**:
  - Name cannot be empty
  - Category ID must exist
  - Name should be unique within the same category

### Licenses
- Core entity representing software licenses
- **Required Relationships**:
  - Must belong to a company (foreign key: company_id)
  - Must have a type (foreign key: type_id)
- **Optional Relationships**:
  - Can be assigned to a unit (foreign key: unit_id, nullable)
- **Constraints**:
  - Cannot exist without a company
  - Cannot exist without a type
  - End date must be after start date
  - Cannot be assigned to archived companies
- **Validations**:
  - Name cannot be empty
  - Product key cannot be empty
  - Start date must be valid
  - End date must be valid and after start date
  - Company ID must exist
  - Type ID must exist
  - Unit ID (if provided) must exist

## Business Rules

### Company Management
1. **Archiving**:
   - Archived companies:
     - Cannot receive new licenses
     - Existing licenses become inactive
     - Units remain but are considered inactive
   - Can be unarchived to restore operations
2. **Deletion**:
   - Permanent deletion requires:
     - Company to be archived first
     - Manual confirmation
     - Administrative privileges

### License Management
1. **Assignment Rules**:
   - Licenses can be:
     - Company-wide (no unit_id)
     - Unit-specific (has unit_id)
   - Cannot be assigned to archived companies
2. **Expiration Handling**:
   - System tracks:
     - Active licenses
     - Expiring soon (configurable threshold)
     - Expired licenses
3. **License Status**:
   - Active: Current date between start_date and end_date
   - Expiring Soon: Within 30 days of end_date
   - Expired: Current date past end_date

### Unit Management
1. **Unit Operations**:
   - Units can only be managed if company is active
   - Unit deletion requires:
     - No active licenses assigned
     - Administrative confirmation
2. **License Association**:
   - Units can have multiple licenses
   - Licenses can be transferred between units
   - Unit deletion unassigns licenses (not deletes)

### Category and Type Management
1. **Category Operations**:
   - Categories can only be deleted if no types exist
   - Category names must be unique
2. **Type Operations**:
   - Types can only be deleted if no licenses exist
   - Type names must be unique within category
   - Moving types between categories is not allowed

## Validation Rules

### Common Validations
- All IDs must be valid UUIDs
- All names must be between 1 and 255 characters
- All timestamps must be valid ISO dates
- All required fields must be non-empty

### Specific Entity Validations

#### Company
```go
type Company struct {
    ID         string     // UUID, required
    Name       string     // Required, 1-255 chars
    CNPJ       string     // Required, valid format XX.XXX.XXX/XXXX-XX
    ArchivedAt *time.Time // Optional, must be valid timestamp if present
}
```

#### Unit
```go
type Unit struct {
    ID        string // UUID, required
    Name      string // Required, 1-255 chars
    CompanyID string // Required, must exist in companies table
}
```

#### Category
```go
type Category struct {
    ID   string // UUID, required
    Name string // Required, 1-255 chars, unique
}
```

#### Type
```go
type Type struct {
    ID         string // UUID, required
    Name       string // Required, 1-255 chars, unique in category
    CategoryID string // Required, must exist in categories table
}
```

#### License
```go
type License struct {
    ID         string    // UUID, required
    Name       string    // Required, 1-255 chars
    ProductKey string    // Required, 1-255 chars
    StartDate  time.Time // Required, valid date
    EndDate    time.Time // Required, valid date > StartDate
    TypeID     string    // Required, must exist in types table
    CompanyID  string    // Required, must exist in companies table
    UnitID     *string   // Optional, must exist in units table if present
}
```

## Error Handling

### Common Error Types
1. **ValidationError**
   - Invalid input data
   - Missing required fields
   - Invalid format/length
2. **NotFoundError**
   - Entity does not exist
   - Parent entity not found
3. **ConstraintError**
   - Unique constraint violation
   - Foreign key constraint violation
4. **StateError**
   - Invalid state transition
   - Operation not allowed in current state

### Error Responses
- All errors include:
  - Error type
  - Descriptive message
  - Additional context when relevant
- Validation errors specify:
  - Field(s) that failed
  - Reason for failure
  - Expected format/values

## Best Practices

### Database Operations
1. Always use transactions for multi-table operations
2. Verify existence of required relationships
3. Handle soft deletes appropriately
4. Check for constraint violations before operations
5. Use prepared statements for all queries

### Data Validation
1. Validate all input before database operations
2. Check foreign key existence before inserts/updates
3. Verify business rules compliance
4. Sanitize input data
5. Validate date ranges and timestamps

### Error Handling
1. Return specific error types
2. Include context in error messages
3. Log detailed error information
4. Handle transaction rollbacks
5. Maintain audit trail of operations