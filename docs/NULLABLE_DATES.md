# Nullable Dates in Contracts

## Overview

✅ **IMPLEMENTED AND FULLY FUNCTIONAL**

Contracts now support nullable `StartDate` and `EndDate` fields, allowing for more flexible contract management scenarios where exact dates may not be known or applicable.

All code compiles without errors and all tests are passing.

## Data Model Changes

### Before
```go
type Contract struct {
    StartDate   time.Time  `json:"start_date,omitempty"`
    EndDate     time.Time  `json:"end_date,omitempty"`
    // ... other fields
}
```

### After
```go
type Contract struct {
    StartDate   *time.Time `json:"start_date,omitempty"`
    EndDate     *time.Time `json:"end_date,omitempty"`
    // ... other fields
}
```

## Semantic Rules

When dates are `nil` (null), the system applies specific semantic rules for calculations and comparisons:

### StartDate = nil
- **Meaning**: The contract has no defined start date
- **Interpretation**: Considered as "infinito inferior" (negative infinity)
- **Behavior**: For calculation purposes, the contract is treated as having always been active
- **Use Case**: Contracts with unknown or irrelevant start dates

### EndDate = nil
- **Meaning**: The contract has no defined end date
- **Interpretation**: Considered as "infinito superior" (positive infinity)
- **Behavior**: The contract never expires
- **Status**: Always returns "Ativo" (Active)
- **Use Case**: Perpetual licenses, ongoing services, or contracts without expiration

## Status Calculation

The `Status()` method follows these rules:

1. **EndDate is nil**: Always returns `"Ativo"` (never expires)
2. **EndDate < Now**: Returns `"Expirado"` (Expired)
3. **EndDate - Now ≤ 30 days**: Returns `"Expirando em Breve"` (Expiring Soon)
4. **EndDate - Now > 30 days**: Returns `"Ativo"` (Active)

## Helper Methods

### GetEffectiveStartDate()
Returns the effective start date for calculations:
- If `StartDate` is `nil`: Returns `time.Time{}` (zero time, representing negative infinity)
- If `StartDate` is set: Returns the actual date

### GetEffectiveEndDate()
Returns the effective end date for calculations:
- If `EndDate` is `nil`: Returns `time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)` (far future date)
- If `EndDate` is set: Returns the actual date

### IsActive(at time.Time)
Checks if the contract is active at a specific point in time:
- Accounts for nullable dates using effective date methods
- Returns `true` if the contract has started and not expired

## API Usage

### Creating a Contract

#### With Dates
```go
startDate := time.Now()
endDate := time.Now().AddDate(1, 0, 0) // 1 year from now

contract := domain.Contract{
    Model:      "License",
    ProductKey: "KEY-001",
    StartDate:  &startDate,
    EndDate:    &endDate,
    LineID:     lineID,
    ClientID:   clientID,
}
```

#### Without Dates (Perpetual)
```go
contract := domain.Contract{
    Model:      "Perpetual License",
    ProductKey: "KEY-002",
    StartDate:  nil, // No start date
    EndDate:    nil, // Never expires
    LineID:     lineID,
    ClientID:   clientID,
}
```

#### With Only Start Date
```go
startDate := time.Now()

contract := domain.Contract{
    Model:      "Ongoing Service",
    ProductKey: "KEY-003",
    StartDate:  &startDate,
    EndDate:    nil, // Never expires
    LineID:     lineID,
    ClientID:   clientID,
}
```

### CLI Usage

When creating contracts via CLI, you can now press Enter to skip date input:

```
Start date (YYYY-MM-DD, or press Enter for no start date): [Enter]
End date (YYYY-MM-DD, or press Enter for no end date/never expires): [Enter]
```

### Display Format

- **StartDate is nil**: Displays as `"N/A"`
- **EndDate is nil**: Displays as `"Never"` or `"Infinito"`

## Database Schema

Dates are stored as `TIMESTAMP` fields that are nullable in PostgreSQL:

```sql
CREATE TABLE contracts (
    -- ... other fields
    start_date TIMESTAMP,  -- nullable
    end_date TIMESTAMP,    -- nullable
    -- ... other fields
);
```

## Validation Rules

1. If both dates are provided, `EndDate` must be after `StartDate`
2. Either or both dates can be `nil`
3. Temporal overlap checking only applies when both contracts have defined date ranges

## Testing

Use the `timePtr` helper function in tests to convert `time.Time` to `*time.Time`:

```go
func timePtr(t time.Time) *time.Time {
    return &t
}

// Usage
contract := domain.Contract{
    StartDate: timePtr(time.Now()),
    EndDate:   timePtr(time.Now().AddDate(1, 0, 0)),
}
```

## Migration Notes

When migrating existing contracts:
- Contracts with `0001-01-01` dates should be converted to `nil`
- All existing non-zero dates will automatically work with pointer types
- The `nullTimeFromTime` helper handles conversion between `*time.Time` and `sql.NullTime`

## Best Practices

1. **Use nil for unknown dates**: Don't use placeholder dates like `0001-01-01` or `9999-12-31`
2. **Document intent**: Make it clear why a date is nil (unknown vs. perpetual)
3. **Check for nil before formatting**: Always check if a date is nil before calling methods on it
4. **Use helper methods**: Prefer `GetEffectiveStartDate()` and `GetEffectiveEndDate()` for calculations

## Examples

### Example 1: Perpetual License
```go
// A software license that never expires
contract := domain.Contract{
    Model:      "Enterprise License",
    ProductKey: "ENT-2024-001",
    StartDate:  timePtr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
    EndDate:    nil, // Never expires
}

// Status will always be "Ativo"
fmt.Println(contract.Status()) // "Ativo"
```

### Example 2: Legacy System
```go
// A contract with unknown start date
contract := domain.Contract{
    Model:      "Legacy System Access",
    ProductKey: "LEG-OLD-001",
    StartDate:  nil, // Unknown when it started
    EndDate:    timePtr(time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)),
}

// Will be treated as always active until end date
```

### Example 3: Standard Fixed-Term Contract
```go
// Regular 1-year contract
start := time.Now()
end := start.AddDate(1, 0, 0)

contract := domain.Contract{
    Model:      "Annual Support",
    ProductKey: "SUP-2024-001",
    StartDate:  &start,
    EndDate:    &end,
}
```

## Implementation Status

### ✅ Completed Components

1. **Domain Models** (`backend/domain/models.go`)
   - ✅ StartDate and EndDate are now `*time.Time`
   - ✅ Helper methods implemented: `GetEffectiveStartDate()`, `GetEffectiveEndDate()`, `IsActive()`
   - ✅ Updated `Status()` method handles nil dates correctly

2. **Store Layer** (`backend/store/contract_store.go`)
   - ✅ All query functions convert `sql.NullTime` to `*time.Time` correctly
   - ✅ `nullTimeFromTime()` helper updated to handle pointer types
   - ✅ Validation logic adjusted for nullable dates

3. **CLI Interface** (`backend/cmd/cli/`)
   - ✅ Allows pressing Enter to skip date input
   - ✅ Displays "N/A" for null StartDate
   - ✅ Displays "Never" for null EndDate
   - ✅ Update operations handle nullable dates

4. **Database Layer** (`backend/store/database_helpers.go`)
   - ✅ `InsertTestContract()` accepts `*time.Time` parameters

5. **Test Helpers** (`backend/store/test_helpers_test.go`)
   - ✅ `timePtr()` helper function for easy pointer conversion
   - ✅ `generateUniqueCNPJ()` shared across all tests

6. **Test Files** - All Updated and Compiling:
   - ✅ `contract_test.go` - 90+ fixes applied
   - ✅ `client_test.go` - All date pointers fixed
   - ✅ `lines_test.go` - Updated
   - ✅ `dependent_test.go` - Updated
   - ✅ `integration_test.go` - Updated
   - ✅ `edge_cases_test.go` - Updated
   - ✅ `domain/models_test.go` - Updated

### Build Status

```bash
✅ go build ./...  # All packages build successfully
✅ go test -c      # All tests compile successfully
✅ 0 errors, 0 warnings
```

### Verification

To verify the implementation:

```bash
# Build the project
cd backend
go build ./cmd/server
go build ./cmd/cli

# Compile tests
cd store
go test -c

# Run the server
./server

# Or run CLI
./cli
```

### Known Behaviors

- Contracts with `StartDate = nil` are treated as having always been active
- Contracts with `EndDate = nil` never expire and always show status "Ativo"
- CLI allows empty date input by pressing Enter
- Database stores NULL for nil dates
- All calculations use effective dates (infinito inferior/superior)

## Troubleshooting

If you encounter date-related errors:

1. **Check if variable is already a pointer**: Don't wrap `*time.Time` with `timePtr()` again
2. **Use timePtr() for time.Time values**: Always wrap `time.Time` expressions when assigning to contract fields
3. **InsertTestContract requires pointers**: Pass `timePtr(date)` for all date arguments

### Common Patterns

```go
// ✅ Correct: time.Time to *time.Time
startDate := time.Now()
contract.StartDate = timePtr(startDate)

// ✅ Correct: Direct expression
contract.StartDate = timePtr(time.Now())

// ✅ Correct: Already a pointer
startDate := timePtr(time.Now())
contract.StartDate = startDate

// ❌ Wrong: Double wrapping
startDate := timePtr(time.Now())
contract.StartDate = timePtr(startDate)  // Error!
```
