# Store Package Reference

## Overview

The store package implements database operations and business rules for the License Management System. This document details all operations, constraints, validations, and relationships between entities.

## Database Relationships & Constraints

### Clients
- Primary entity that owns licenses and entities
- Each client must have:
  - Unique registration_id
  - Non-empty name
  - Creation date (auto-generated)
- Optional archived_at timestamp for soft deletion
- **Cascade Effects**:
  - Deleting a client will delete all its:
    - Entities
    - Licenses
    - Related data

### Entities (Client Branches)
- Represents physical locations or departments
- **Required Relationships**:
  - Must belong to an existing client (foreign key: client_id)
- **Constraints**:
  - Cannot exist without a client
  - Must have a non-empty name
  - Name should be unique within the same client
- **Cascade Effects**:
  - When a entity is deleted:
    - Associated licenses are updated to remove entity reference (entity_id set to NULL)
    - Does not affect parent client

### Categories
- Classifies license lines
- **Constraints**:
  - Must have unique name
  - Cannot be deleted if has lines associated
- **Validations**:
  - Name cannot be empty
  - Name must be unique (case-insensitive)

### Lines
- Defines specific license lines within categories
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
  - Must belong to a client (foreign key: client_id)
  - Must have a type (foreign key: line_id)
- **Optional Relationships**:
  - Can be assigned to a entity (foreign key: entity_id, nullable)
- **Constraints**:
  - Cannot exist without a client
  - Cannot exist without a line
  - End date must be after start date
  - Cannot be assigned to archived clients
- **Validations**:
  - Name cannot be empty
  - Product key cannot be empty
  - Start date must be valid
  - End date must be valid and after start date
  - Client ID must exist
  - Line ID must exist
  - Entity ID (if provided) must exist

## Business Rules

### Client Management
1. **Archiving**:
   - Archived clients:
     - Cannot receive new licenses
     - Existing licenses become inactive
     - Entities remain but are considered inactive
   - Can be unarchived to restore operations
2. **Deletion**:
   - Permanent deletion requires:
     - Client to be archived first
     - Manual confirmation
     - Administrative privileges

### License Management
1. **Assignment Rules**:
   - Licenses can be:
     - Client-wide (no entity_id)
     - Entity-specific (has entity_id)
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

### Entity Management
1. **Entity Operations**:
   - Entities can only be managed if client is active
   - Entity deletion requires:
     - No active licenses assigned
     - Administrative confirmation
2. **License Association**:
   - Entities can have multiple licenses
   - Licenses can be transferred between entities
   - Entity deletion unassigns licenses (not deletes)

### Category and Line Management
1. **Category Operations**:
   - Categories can only be deleted if no lines exist
   - Category names must be unique
2. **Line Operations**:
   - Lines can only be deleted if no licenses exist
   - Line names must be unique within category
   - Moving lines between categories is not allowed

## Validation Rules

### Common Validations
- All IDs must be valid UUIDs
- All names must be between 1 and 255 characters
- All timestamps must be valid ISO dates
- All required fields must be non-empty

### Specific Entity Validations

#### Client
```go
type Client struct {
    ID         string     // UUID, required
    Name       string     // Required, 1-255 chars
    RegistrationID string // Required, valid format for country-specific registration
    ArchivedAt *time.Time // Optional, must be valid timestamp if present
}
```

#### Entity
```go
type Entity struct {
    ID        string // UUID, required
    Name      string // Required, 1-255 chars
    ClientID string // Required, must exist in companies table
}
```

#### Category
```go
type Category struct {
    ID   string // UUID, required
    Name string // Required, 1-255 chars, unique
}
```

#### Line
```go
type Line struct {
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
    LineID     string    // Required, must exist in lines table
    ClientID  string    // Required, must exist in companies table
    EntityID   *string   // Optional, must exist in entities table if present
}
```

## Error Handling

### Common Error Lines
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
  - Error line
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
1. Return specific error lines
2. Include context in error messages
3. Log detailed error information
4. Handle transaction rollbacks
5. Maintain audit trail of operations
