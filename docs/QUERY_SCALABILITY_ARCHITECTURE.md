# Query Scalability Architecture — Client Hub Open Project

## Overview

This document describes the query architecture and scalability patterns used in the Client Hub project, with emphasis on financial queries. It serves as a blueprint for maintaining and extending the system while preventing performance degradation.

---

## The Problem We Solved

### Initial Issue: "Query Bomb" in Financial Page

The original `GetFinancialDetailedSummary()` function was generating **15,000–20,000 SQL queries per request**, causing the Financial dashboard to freeze for **15–30 seconds**. This happened because:

1. **N+1 Query Problem**: For every financial record, the code fetched related installments individually
2. **Nested Loops**: Multiple layers of iteration without batch loading
3. **No Aggregation**: All calculations done in application memory instead of at the database level
4. **Inefficient Date Filtering**: Time-based queries without proper indexing

**After fixes**: Same page now loads in **0.72 seconds** with proper batching, aggregation, and indexing.

---

## Core Scalability Principles

### 1. **Batch Queries Over Individual Fetches**

❌ **Anti-pattern (N+1)**:
```go
// For each of 100 contracts...
for _, contract := range contracts {
    // ...fetch its 5 installments individually
    installments, err := repo.GetInstallmentsByContractID(contract.ID)
}
// Result: 100 queries + 500 installment queries = 600 queries
```

✅ **Correct Pattern (Batch)**:
```go
// Fetch all 500 installments in ONE query
installments, err := repo.GetInstallmentsByContractIDsBatch(contractIDs)
// Result: 1 query
```

**When to use**:
- Loading related data for multiple parent records
- Processing collections of IDs
- Joining across multiple entities

---

### 2. **Aggregate at Database Level, Not Application**

❌ **Anti-pattern (App-level aggregation)**:
```go
var totalPaid float64
for _, installment := range installments {
    if installment.Status == "pago" {
        totalPaid += installment.Value
    }
}
// Loops through thousands of rows in memory
```

✅ **Correct Pattern (SQL aggregation)**:
```sql
SELECT SUM(value) as total_paid
FROM financial_installments
WHERE status = 'pago' AND contract_id = ANY($1)
-- Database engine optimizes this, returns 1 row
```

**When to use**:
- Sums, counts, averages
- Grouping across large datasets
- Time-range queries

---

### 3. **Use Covering Indexes for Large Tables**

❌ **Anti-pattern (No index)**:
```sql
SELECT COUNT(*) FROM financial_installments WHERE status = 'pago';
-- Full table scan (10,000+ rows)
```

✅ **Correct Pattern (Covering index)**:
```sql
-- Create composite covering index
CREATE INDEX idx_installments_status_value_contract 
ON financial_installments (status, contract_id) 
INCLUDE (value, due_date);

-- Query uses index, no table access
SELECT COUNT(*) FROM financial_installments WHERE status = 'pago';
```

**Current indexes** (in schema):
- `idx_financial_installments_contract_status`: Status filtering by contract
- `idx_financial_installments_due_date`: Date range queries
- `idx_financial_installments_status_value`: Status + aggregations

---

### 4. **Pagination for Large Result Sets**

❌ **Anti-pattern (No limit)**:
```go
// Load ALL 5,000 contracts at once
contracts, err := repo.GetAllContracts()
// Memory spike, network bloat, slow rendering
```

✅ **Correct Pattern (Pagination)**:
```go
// Load 20 per page
contracts, total, err := repo.GetContractsPaginated(limit: 20, offset: 0)
// Next page: offset: 20, etc.
```

**Implementation**:
- All list endpoints now support `limit` (default 20, max 500) and `offset`
- Backend returns `{data, total, limit, offset}`
- Frontend implements infinite scroll or page navigation

---

## Financial Query Architecture

### GetFinancialDetailedSummary() — Before vs. After

#### Before: 15,000–20,000 queries, 15–30 seconds

```
1. GetContracts() [1 query]
   ↓
2. For each contract:
   - GetFinancialByContractID() [~2,500 queries]
   - For each financial:
     - GetInstallmentsByFinancialID() [~15,000 queries]
     - For each installment:
       - Calculate status, aggregate [in-memory]
3. SUM in application loop [slow]
```

#### After: 4–5 queries, ~0.72 seconds

```
1. GetContracts() [1 query]
2. GetFinancialsByContractIDBatch(contractIDs) [1 query, JOIN optimized]
3. GetInstallmentsByContractIDBatch(contractIDs) [1 query, aggregate in SQL]
4. GetInstallmentsByDueDateRanges(dateRanges) [1-2 queries for range filtering]
```

### Key Changes

| Aspect | Before | After |
|--------|--------|-------|
| **Queries** | 15,000–20,000 | 4–5 |
| **Load Time** | 15–30 sec | 0.72 sec |
| **Approach** | N+1, app aggregation | Batch, SQL aggregation |
| **Indexing** | Minimal | Covering indexes on status, date ranges |
| **Memory** | Thousands of objects | Only results needed |

---

## Repository Layer: Batch Query Methods

### Naming Convention

```go
// Single entity
GetFinancialByID(id string) (*Financial, error)

// Multiple entities (batch)
GetFinancialsByIDBatch(ids []string) ([]*Financial, error)

// All (use with caution, only for small tables)
GetAllFinancials() ([]*Financial, error)

// Paginated (preferred for large lists)
GetFinancialsPaginated(limit, offset int) ([]*Financial, int, error)

// Aggregated (count, sum, group by)
GetInstallmentsSummaryByStatus(contractIDs []string) (map[string]int, error)
```

### Example: Financial Installments Batch Query

```go
// GetInstallmentsByContractIDBatch fetches all installments for multiple contracts
// in a single query, using SQL ANY() for efficient filtering.
func (r *FinancialStore) GetInstallmentsByContractIDBatch(
    ctx context.Context,
    contractIDs []string,
) ([]*Installment, error) {
    query := `
        SELECT id, financial_id, contract_id, due_date, value, status, paid_date
        FROM financial_installments
        WHERE contract_id = ANY($1)
        ORDER BY contract_id, due_date
    `
    rows, err := r.db.QueryContext(ctx, query, pq.Array(contractIDs))
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var installments []*Installment
    for rows.Next() {
        var inst Installment
        if err := rows.Scan(&inst.ID, &inst.FinancialID, &inst.ContractID, 
            &inst.DueDate, &inst.Value, &inst.Status, &inst.PaidDate); err != nil {
            return nil, err
        }
        installments = append(installments, &inst)
    }
    return installments, rows.Err()
}
```

---

## SQL Aggregation Patterns

### Pattern 1: Status-Based Aggregations

```sql
-- Get count and sum by status
SELECT 
    status,
    COUNT(*) as count,
    SUM(value) as total_value
FROM financial_installments
WHERE contract_id = ANY($1)
GROUP BY status;
```

### Pattern 2: Date Range Grouping

```sql
-- Monthly summary: past, current, next
WITH monthly_data AS (
    SELECT 
        DATE_TRUNC('month', due_date) as month,
        SUM(value) as total,
        COUNT(*) as count
    FROM financial_installments
    WHERE contract_id = ANY($1)
      AND due_date >= CURRENT_DATE - INTERVAL '30 days'
      AND due_date <= CURRENT_DATE + INTERVAL '90 days'
    GROUP BY DATE_TRUNC('month', due_date)
)
SELECT * FROM monthly_data ORDER BY month;
```

### Pattern 3: Covering Index for Multi-Column Filters

```sql
-- Index definition (covers: status, contract_id, value, due_date)
CREATE INDEX idx_installments_status_value_contract 
ON financial_installments (status, contract_id) 
INCLUDE (value, due_date);

-- Query benefits from covering index (no table access)
SELECT SUM(value) as total
FROM financial_installments
WHERE status = 'pago' AND contract_id = ANY($1);
```

---

## Frontend Query Patterns

### Don't: Fire Multiple Requests in Parallel

```javascript
// ❌ Anti-pattern: 4 concurrent requests, rate-limited
const financial = await financialApi.loadFinancial(apiUrl, token);
const summary = await financialApi.getFinancialSummary(apiUrl, token);
const monthly = await financialApi.getMonthlySummary(apiUrl, token, year, month);
const upcoming = await financialApi.getUpcomingFinancial(apiUrl, token);
```

### Do: Batch Frontend Requests or Use Endpoints That Return Multiple Data

```javascript
// ✅ Better: Single endpoint returns dashboard data
const dashboard = await financialApi.getDashboard(apiUrl, token);
// Returns: { financial: [...], summary: {...}, monthly: {...} }
```

Or, if multiple endpoints are needed:

```javascript
// ✅ Acceptable: Sequential loading with proper error handling
try {
    const financial = await financialApi.loadFinancial(apiUrl, token);
    const summary = await financialApi.getFinancialSummary(apiUrl, token);
} catch (err) {
    if (err.message.includes("Excesso de requisições")) {
        // Handle rate limit: show message, wait, retry
        showRateLimitMessage();
    }
}
```

---

## Scalability Projections

### Current Performance Baseline (as of this update)

| Page | Query Count | Load Time | Status |
|------|------------|-----------|--------|
| Contracts List | 2–3 | <500ms | ✅ Optimized |
| Financial Dashboard | 4–5 | 0.72s | ✅ Optimized (from 15-30s) |
| Clients List | 1–2 | <300ms | ✅ Optimized |
| Categories + Subcategories | 2 | <400ms | ✅ Optimized |

### Projection: 10x Data Growth (250,000 contracts)

| Scenario | Query Count | Estimated Time | Mitigation |
|----------|------------|-----------------|-----------|
| Financial Dashboard (no changes) | 4–5 | 0.9–1.2s | ✅ Still acceptable |
| With new indexes | 4–5 | 0.7–0.9s | ✅ Indexes scale well |
| Without pagination | 4–5 | 5–10s | ⚠️ Pagination required |

**Recommendation**: If dataset grows beyond 100,000 records, add incremental aggregation tables (materialized views) for frequently-queried date ranges.

### Projection: 100x Data Growth (2.5M+ contracts)

| Action | Impact |
|--------|--------|
| **Materialized Views** | Precompute monthly/annual summaries, update hourly |
| **Partitioning** | Split `financial_installments` by year, status |
| **Caching Layer** | Redis for dashboard summaries (5-min TTL) |
| **Async Aggregation** | Background job computes slow queries, caches result |

---

## How to Extend This Architecture

### Adding a New Large-Dataset Endpoint

1. **Define the schema**: How many rows? What indexes?
   ```go
   // Example: expenses table with 500k rows
   type Expense struct {
       ID         string
       ContractID string
       Date       time.Time
       Amount     float64
       Category   string
   }
   ```

2. **Design the index**:
   ```sql
   -- For common queries (by contract + date)
   CREATE INDEX idx_expenses_contract_date 
   ON expenses (contract_id, date DESC) 
   INCLUDE (amount, category);
   ```

3. **Implement batch retrieval**:
   ```go
   func (r *ExpenseStore) GetExpensesByContractIDBatch(
       ctx context.Context,
       contractIDs []string,
   ) ([]*Expense, error) { ... }
   ```

4. **Use pagination for lists**:
   ```go
   func (r *ExpenseStore) GetExpensesPaginated(
       limit, offset int,
   ) ([]*Expense, int, error) { ... }
   ```

5. **Test query performance**:
   ```bash
   EXPLAIN ANALYZE SELECT ... FROM expenses WHERE ...;
   ```

---

## Monitoring & Observability

### Slow Query Detection

```sql
-- PostgreSQL: Enable slow query logging
ALTER SYSTEM SET log_min_duration_statement = 500; -- Log queries > 500ms
SELECT pg_reload_conf();

-- View slow queries
SELECT query, mean_time, calls FROM pg_stat_statements 
WHERE mean_time > 500 
ORDER BY mean_time DESC 
LIMIT 10;
```

### Query Metrics to Track

| Metric | Target | Action if Exceeded |
|--------|--------|-------------------|
| Financial dashboard query count | < 10 | Review batch loading |
| Average response time | < 1s | Check indexes, add caching |
| Slow query frequency | < 5% | Analyze query plans |
| API 429 rate-limit hits | < 1% | Increase burst or cache results |

---

## Anti-Patterns to Avoid

| Anti-Pattern | Problem | Solution |
|-------------|---------|----------|
| **SELECT * without limit** | Loads all rows, slow network | Add `LIMIT`, use pagination |
| **N+1 queries** | Exponential query count | Use batch methods |
| **App-level aggregation** | Slow, memory-heavy | Aggregate in SQL |
| **Nested loops with queries** | Query explosion | Refactor to joins or batch |
| **No indexes on filter columns** | Full table scans | Create covering indexes |
| **Hardcoded magic numbers** | Inflexible, unmaintainable | Use config constants |

---

## Summary: The Scalability Checklist

- ✅ Use batch queries (`*Batch` methods) for related data
- ✅ Aggregate in SQL (SUM, COUNT, GROUP BY) not application code
- ✅ Create covering indexes for frequently-filtered columns
- ✅ Implement pagination for any list > 100 rows
- ✅ Monitor slow queries (> 500ms) and investigate
- ✅ Test query performance with `EXPLAIN ANALYZE`
- ✅ Document query assumptions (expected row count, typical filters)
- ✅ Plan for 10x growth: can current indexes handle it?

---

## Related Documentation

- `backend/BACKEND_ARCHITECTURE.md` — Service and handler layer
- `backend/database/QUERIES.md` — SQL query reference
- `PERFORMANCE_SUMMARY.md` — Before/after metrics

---

**Last Updated**: 2025-01-XX  
**Status**: Complete, ready for extension  
**Maintainer**: DevSecOps Team