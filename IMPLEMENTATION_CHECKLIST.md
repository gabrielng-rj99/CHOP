# ✅ Implementation Checklist: Performance Fixes

**Project**: Client Hub Open Project  
**Date**: Janeiro 2025  
**Target Completion**: 7-10 days  
**Phases**: P0 (2-3 days) → P1 (1 day) → P2 (2-3 days)

---

## 🔴 PHASE P0: Desbloquear Financial (2-3 dias)

### Task P0.1: Refatorar `getPeriodSummary()` — Batch Query N+1

**File**: `backend/repository/contract/financial_store.go`  
**Lines**: L826-1028  
**Estimated Time**: 6-8 hours

#### Checklist

- [ ] Create new method `getInstallmentStatusBatch(cfIDs []string, periodStart, periodEnd time.Time)` that:
  - [ ] Takes slice of contract_financial IDs
  - [ ] Executes single query with `WHERE contract_financial_id = ANY($1::uuid[])`
  - [ ] Returns `map[string]map[string]int` (cfID → status → count)
  - [ ] Uses indexes: `idx_financial_installments_financial`, `idx_financial_installments_due_date`

- [ ] Update `getPeriodSummary()` to:
  - [ ] Build list of recurrent IDs that apply to period
  - [ ] Call `getInstallmentStatusBatch()` once instead of per-item loop
  - [ ] Use returned status map to populate summary fields
  - [ ] Remove old `checkInstallment` QueryRow loop

- [ ] Add error handling:
  - [ ] If batch query fails, return error (not silent fail)
  - [ ] Log query execution time for monitoring

- [ ] Write unit tests:
  - [ ] Test with 0 recurrents → no crash
  - [ ] Test with 100+ recurrents → returns correct map
  - [ ] Test with mixed statuses (pago, pendente, atrasado)

- [ ] Validate:
  - [ ] `go fmt backend/...`
  - [ ] `go vet backend/...`
  - [ ] `go test ./backend/repository/contract -v`
  - [ ] All tests pass ✅

**Acceptance**: Query count for 1 period reduced from ~1500 to 1

---

### Task P0.2: Refatorar `GetFinancialDetailedSummary()` — Grouped Query

**File**: `backend/repository/contract/financial_store.go`  
**Lines**: L767-823  
**Estimated Time**: 4-6 hours

#### Checklist

- [ ] Create new method `getPeriodSummaryGrouped()` that:
  - [ ] Takes date range (e.g., -3 to +3 months from today)
  - [ ] Executes ONE query grouping by `DATE_TRUNC('month', due_date)`
  - [ ] Returns `map[string]PeriodSummary` (YYYY-MM → summary)
  - [ ] Uses indexes: `idx_financial_installments_due_date`

- [ ] SQL query structure:
  ```sql
  SELECT
    DATE_TRUNC('month', pi.due_date)::date as month,
    COALESCE(SUM(pi.received_value), 0) as total_to_receive,
    -- other aggregates...
  FROM financial_installments pi
  WHERE pi.due_date >= (CURRENT_DATE - INTERVAL '3 months')
    AND pi.due_date < (CURRENT_DATE + INTERVAL '4 months')
  GROUP BY DATE_TRUNC('month', pi.due_date)
  ```

- [ ] Update `GetFinancialDetailedSummary()` to:
  - [ ] Replace 10 `getPeriodSummary()` calls with 1 `getPeriodSummaryGrouped()` call
  - [ ] Populate `LastMonth`, `CurrentMonth`, `NextMonth`, `MonthlyBreakdown` from result map
  - [ ] Remove old loop: `for i := -3; i <= 3; i++`

- [ ] Handle recurring financials:
  - [ ] Determine if recurring logic needs to be in grouped query or separate
  - [ ] If separate, batch the recurrent calculations after grouping

- [ ] Write unit tests:
  - [ ] Test returns correct 7 months (last 3 + current + next 3)
  - [ ] Test aggregations are correct (SUM, COUNT)
  - [ ] Test empty period (no data) doesn't crash

- [ ] Validate:
  - [ ] `go fmt backend/...`
  - [ ] `go vet backend/...`
  - [ ] `go test ./backend/repository/contract -v`
  - [ ] All tests pass ✅

**Acceptance**: Query count for DetailedSummary reduced from ~150 to 2-3

---

### Task P0.3: Implementar Paginação em `handleListFinancial()`

**File**: `backend/server/financial_handlers.go` (L46-60) + `financial_store.go` (new methods)  
**Estimated Time**: 3-4 hours

#### Checklist

- [ ] Update `handleListFinancial()` handler:
  - [ ] Call `parseLimitOffset(r, 20, 500)` to get limit (default 20, max 500)
  - [ ] Call `s.financialStore.GetAllFinancialsPaged(limit, offset)` (new method)
  - [ ] Call `s.financialStore.CountFinancials()` (new method)
  - [ ] Return response with `{data, total, limit, offset}`

- [ ] Create `GetAllFinancialsPaged()` method:
  - [ ] Query with `ORDER BY created_at DESC LIMIT $1 OFFSET $2`
  - [ ] Return only requested slice (20-100 records)
  - [ ] Do NOT call `calculateFinancialTotals()` per record (future work)

- [ ] Create `CountFinancials()` method:
  - [ ] Simple `SELECT COUNT(*) FROM contract_financial...`
  - [ ] Cache in `handleListFinancial()` or let it execute fresh

- [ ] Query validation:
  - [ ] Test LIMIT/OFFSET work correctly
  - [ ] Test total count is accurate
  - [ ] Test ordering is consistent

- [ ] Write tests:
  - [ ] Test with limit=20, offset=0 → returns 20 records
  - [ ] Test with offset=4380, limit=20 → returns remaining records
  - [ ] Test total count is correct

- [ ] Validate:
  - [ ] `go fmt`, `go vet`, `go test` all pass ✅

**Acceptance**: `/api/financial` returns 20-100 records max, not 4387

---

### Task P0.4: Testing & Validation

**Estimated Time**: 2 hours

#### Checklist

- [ ] Run full backend test suite:
  ```bash
  go test ./backend/... -v -count=1
  ```
  - [ ] All tests pass ✅
  - [ ] No timeout errors
  - [ ] No race conditions

- [ ] Load test Financial page endpoints:
  - [ ] Measure query count before/after with logging
  - [ ] Measure response time (should be <2s for detailedSummary)
  - [ ] Check PostgreSQL logs for slow queries (>100ms)

- [ ] Verify backward compatibility:
  - [ ] Dashboard counts still work
  - [ ] Other endpoints unaffected
  - [ ] Frontend still receives expected response shape

- [ ] Code review checklist:
  - [ ] No hardcoded SQL (all parameterized)
  - [ ] No N+1 patterns introduced
  - [ ] Error handling in place
  - [ ] Index usage confirmed in EXPLAIN ANALYZE

- [ ] Documentation:
  - [ ] Add comments to new methods
  - [ ] Update API docs if needed

---

## 🟡 PHASE P1: Corrigir Categories (1 dia)

### Task P1.1: Remover `loadAllLinesInBackground()` do Frontend

**File**: `frontend/src/pages/Categories.jsx`  
**Lines**: L158-179  
**Estimated Time**: 1-2 hours

#### Checklist

- [ ] Analyze current usage of `loadAllLinesInBackground()`:
  - [ ] Called in `loadCategories()` at L177
  - [ ] Sets `allLines` state
  - [ ] Marks `allLinesLoadedRef.current = true`

- [ ] Verify backend response structure:
  - [ ] Fetch one category response in browser DevTools
  - [ ] Confirm `lines` field exists with subcategories
  - [ ] Confirm structure matches expected shape

- [ ] Update `loadCategories()` function:
  ```javascript
  // OLD:
  loadAllLinesInBackground(data, forceRefresh);
  
  // NEW:
  const flattenedLines = data.flatMap(cat => cat.lines || []);
  setAllLines(flattenedLines);
  allLinesLoadedRef.current = true;
  ```

- [ ] Remove function definition:
  - [ ] Delete entire `loadAllLinesInBackground` function (L158-179)
  - [ ] Remove from deps in useCallback: `[fetchSubcategories]`

- [ ] Test in browser:
  - [ ] Load Categories page
  - [ ] Check Network tab: should see 1 request to `/api/categories`, no additional requests
  - [ ] Verify categories and subcategories both display
  - [ ] Re-visit Categories: should be instant (cache hit)

- [ ] Validate:
  - [ ] `npm test -- Categories` passes
  - [ ] `npm run lint` passes
  - [ ] No console errors

**Acceptance**: 0 additional HTTP calls for subcategories

---

### Task P1.2: Testing & Validation

**Estimated Time**: 30 minutes

#### Checklist

- [ ] Functional testing:
  - [ ] Categories load without extra requests
  - [ ] Search by category name works
  - [ ] Search by subcategory name works (uses `allLines`)
  - [ ] Re-visit is instant

- [ ] Browser DevTools validation:
  - [ ] Network tab shows only 1 request to `/api/categories`
  - [ ] No 2010 individual `/api/subcategories/[id]` requests
  - [ ] Performance tab shows <500ms load time

- [ ] Run tests:
  - [ ] `npm test -- Categories`
  - [ ] `npm run lint`

---

## 🟡 PHASE P2: Melhorar Financial UX (2-3 dias)

### Task P2.1: Lazy-load `detailedSummary`

**File**: `frontend/src/pages/Financial.jsx`  
**Lines**: L228-272  
**Estimated Time**: 3-4 hours

#### Checklist

- [ ] Identify where `detailedData` is used:
  - [ ] Grep for `detailedSummary` in file
  - [ ] Find which tabs/sections depend on it
  - [ ] Verify it's only rendered in "monthlyBreakdown" view (around L1300-1500)

- [ ] Remove from initial `loadData()`:
  ```javascript
  // OLD:
  const [... detailedData, ...] = await Promise.all([
    financialApi.loadFinancial(...),
    ...,
    financialApi.getDetailedSummary(...),  // ← REMOVE
    ...
  ]);
  
  // NEW:
  const [... /* no detailedData */] = await Promise.all([
    financialApi.loadFinancial(...),
    ...,
    // ← removed getDetailedSummary
    ...
  ]);
  ```

- [ ] Don't set `detailedSummary` in initial load:
  - [ ] Remove `setDetailedSummary(detailedData)` line

- [ ] Create new `loadDetailedSummary()` function:
  ```javascript
  const loadDetailedSummary = async () => {
    try {
      const data = await financialApi.getDetailedSummary(apiUrl, token, onTokenExpired);
      setDetailedSummary(data);
    } catch (err) {
      console.error("Failed to load detailed summary:", err);
      // Don't block rest of page
    }
  };
  ```

- [ ] Add effect to load on demand:
  ```javascript
  useEffect(() => {
    if (mainTab === "monthlyBreakdown" && !detailedSummary) {
      loadDetailedSummary();
    }
  }, [mainTab, detailedSummary]);
  ```

- [ ] Test:
  - [ ] Financial page loads fast (without waiting for detailed summary)
  - [ ] Clicking "monthlyBreakdown" tab triggers load
  - [ ] Data appears when loaded
  - [ ] Switching tabs doesn't reload (cached)

**Acceptance**: Initial page load <2s, detailedSummary loads on-demand

---

### Task P2.2: Server-side Filtering in Financial

**File**: `backend/server/financial_handlers.go` + `financial_store.go`  
**Estimated Time**: 6-8 hours

#### Checklist

- [ ] Update `handleListFinancial()` to extract filter params:
  ```go
  financialType := r.URL.Query().Get("financial_type")
  status := r.URL.Query().Get("status")
  clientID := r.URL.Query().Get("client_id")
  contractID := r.URL.Query().Get("contract_id")
  ```

- [ ] Create `ListFinancialFiltered()` method in store:
  - [ ] Build WHERE clause dynamically based on params
  - [ ] Support: `financial_type`, `status`, `client_id`, `contract_id`, etc.
  - [ ] Apply `LIMIT` and `OFFSET`
  - [ ] Return only filtered records

- [ ] Create `CountFinancialFiltered()` method:
  - [ ] Same WHERE clause as `ListFinancialFiltered()`
  - [ ] Return total count matching filters

- [ ] Update response:
  ```go
  respondJSON(w, http.StatusOK, map[string]interface{}{
      "data":   financials,
      "total":  total,    // filtered total, not all 4387
      "limit":  limit,
      "offset": offset,
  })
  ```

- [ ] Update frontend to pass filters:
  ```javascript
  const params = {
    limit: itemsPerPage,
    offset: (currentPage - 1) * itemsPerPage,
  };
  if (financialTypeFilter) params.financial_type = financialTypeFilter;
  if (statusFilter) params.status = statusFilter;
  // ... other filters
  
  const response = await financialApi.loadFinancial(apiUrl, token, params);
  ```

- [ ] Remove client-side filtering:
  - [ ] Delete `const filteredFinancial = financialRecords.filter(...)` loop
  - [ ] Use `response.data` directly

- [ ] Test:
  - [ ] Test filter by financial_type
  - [ ] Test filter by status
  - [ ] Test filter by client
  - [ ] Test combined filters
  - [ ] Test pagination with filters

**Acceptance**: Filtering returns results in <500ms, not blocking UI

---

### Task P2.3: Testing & Validation

**Estimated Time**: 2 hours

#### Checklist

- [ ] Functional testing:
  - [ ] Financial page loads fast initially
  - [ ] Clicking monthlyBreakdown tab loads detailed summary
  - [ ] Filtering works for all filter types
  - [ ] Pagination works with filters
  - [ ] No duplicate loads (cache working)

- [ ] Performance testing:
  - [ ] Initial load: <2s
  - [ ] Filtering: <500ms
  - [ ] DetailedSummary on-demand: <2s
  - [ ] Measure query counts before/after

- [ ] Browser testing:
  - [ ] Network tab shows reduced request count
  - [ ] No 20k+ query spike
  - [ ] Performance profiler shows smooth interactions

- [ ] Run tests:
  - [ ] `npm test -- Financial`
  - [ ] `npm run lint`
  - [ ] `go test ./backend/...`

---

## 📊 Cross-Phase Validation

### Before Starting Any Phase

- [ ] Read `PERFORMANCE_DIAGNOSIS.md` completely
- [ ] Understand root causes (not just symptoms)
- [ ] Get database credentials for testing

### After Each Phase

- [ ] All unit tests pass
- [ ] No linting errors
- [ ] No console warnings in browser
- [ ] Backward compatibility verified
- [ ] Documentation updated

### Final Acceptance (All Phases Complete)

- [ ] Financial page loads in <2 seconds
- [ ] Categories page loads in <500ms
- [ ] No N+1 queries remain
- [ ] Dashboard works without issues
- [ ] 0 new performance regressions
- [ ] All tests pass on CI/CD

---

## 🔧 Tools & Commands Reference

### Backend (Go)

```bash
# Run all tests
go test ./backend/... -v -count=1

# Run specific package tests
go test ./backend/repository/contract/... -v

# Format code
go fmt ./backend/...

# Lint
go vet ./backend/...

# Check for SQL query count (add logging in code)
grep -n "QueryRow\|Query" backend/repository/contract/financial_store.go
```

### Frontend (Node/React)

```bash
# Run tests
npm test -- Categories
npm test -- Financial

# Lint
npm run lint
npm run lint -- --fix

# Build
npm run build

# Check bundle size
npm run build -- --analyze
```

### Database (PostgreSQL)

```bash
# Connect to dev database
psql -h localhost -U user -d ehopdb_dev

# Check query performance
EXPLAIN ANALYZE SELECT ... FROM financial_installments WHERE ...;

# Check index usage
SELECT * FROM pg_stat_user_indexes WHERE schemaname='public';
```

---

## 📋 Sign-Off Checklist

### P0 Complete

- [ ] All 4 tasks (P0.1-P0.4) completed and tested
- [ ] No regressions in other endpoints
- [ ] Financial DetailedSummary loads in <2s
- [ ] Code reviewed and approved

### P1 Complete

- [ ] Task P1.1 completed and tested
- [ ] Categories loads in <500ms
- [ ] 0 unnecessary HTTP calls
- [ ] Code reviewed and approved

### P2 Complete

- [ ] All 3 tasks (P2.1-P2.3) completed and tested
- [ ] Financial UX responsive and fast
- [ ] No blocking filters
- [ ] Code reviewed and approved

### All Phases Complete

- [ ] Update `PERFORMANCE_OPTIMIZATION_GUIDE.md` with final status
- [ ] Create PR summary with before/after metrics
- [ ] Document any future improvements identified
- [ ] Schedule performance monitoring setup

---

**Owner**: Backend team for P0, Frontend team for P1/P2  
**Next Review**: After each phase completion  
**Emergency Contact**: [To be filled in]

---

**Document Version**: 1.0  
**Created**: Janeiro 2025  
**Last Updated**: [Current date]