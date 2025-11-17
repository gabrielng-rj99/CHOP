# Implementation Checklist for Monolith Mode

Use this checklist to track progress on implementing Monolith Mode functions.

## Phase 1: Database Management Functions

### PostgreSQL Service Control

- [ ] `monolithStartDatabase()`
  - [ ] Detect OS (Linux vs macOS)
  - [ ] Call appropriate start command
  - [ ] Wait for readiness
  - [ ] Test connection
  - [ ] Report success/failure
  - **Effort**: 1-2 hours

- [ ] `monolithStopDatabase()`
  - [ ] Detect OS
  - [ ] Call stop command
  - [ ] Verify stopped
  - [ ] Report success
  - **Effort**: 30 minutes

- [ ] `monolithRestartDatabase()`
  - [ ] Call stop + sleep + start
  - **Effort**: 15 minutes

- [ ] `monolithDatabaseStatus()`
  - [ ] Test connection
  - [ ] Get version info
  - [ ] Get database list
  - [ ] Report status
  - **Effort**: 1 hour

**Subtotal Phase 1**: ~3-4 hours

---

## Phase 2: Backend Management Functions

### Go API Control

- [ ] `monolithStartBackend()`
  - [ ] Get project root
  - [ ] Change to backend dir
  - [ ] Start go run in background
  - [ ] Redirect output to log file
  - [ ] Store PID
  - [ ] Wait for /health endpoint
  - [ ] Report success
  - **Effort**: 2-3 hours

- [ ] `monolithStopBackend()`
  - [ ] Load saved PID
  - [ ] Kill process gracefully
  - [ ] Force kill if needed
  - [ ] Clean up PID file
  - [ ] Report success
  - **Effort**: 1-1.5 hours

- [ ] `monolithRestartBackend()`
  - [ ] Call stop + sleep + start
  - **Effort**: 15 minutes

- [ ] Helper: `savePID(service, pid)`
  - [ ] Save to `/tmp/contract_manager_{service}.pid`
  - **Effort**: 15 minutes

- [ ] Helper: `loadPID(service)`
  - [ ] Load from `/tmp/contract_manager_{service}.pid`
  - [ ] Return 0 if not found
  - **Effort**: 15 minutes

- [ ] Helper: `findProcessByPort(port)`
  - [ ] Use `lsof -ti :{port}`
  - **Effort**: 30 minutes

**Subtotal Phase 2**: ~4-5 hours

---

## Phase 3: Frontend Management Functions

### Node.js Dev Server Control

- [ ] `monolithStartFrontend()`
  - [ ] Get project root
  - [ ] Change to frontend dir
  - [ ] Start npm run dev in background
  - [ ] Redirect output to log file
  - [ ] Store PID
  - [ ] Wait for port 5173 ready
  - [ ] Report success
  - **Effort**: 2-3 hours

- [ ] `monolithStopFrontend()`
  - [ ] Load saved PID
  - [ ] Kill process gracefully
  - [ ] Clean up
  - [ ] Report success
  - **Effort**: 1 hour

- [ ] `monolithRestartFrontend()`
  - [ ] Call stop + sleep + start
  - **Effort**: 15 minutes

**Subtotal Phase 3**: ~3-4 hours

---

## Phase 4: Service Status and Logs

### Combined Operations

- [ ] `monolithStartAll()`
  - [ ] Start database
  - [ ] Wait 3 seconds
  - [ ] Start backend
  - [ ] Wait 2 seconds
  - [ ] Start frontend
  - [ ] Display URLs
  - **Effort**: 30 minutes

- [ ] `monolithStopAll()`
  - [ ] Stop frontend
  - [ ] Stop backend
  - [ ] Stop database
  - [ ] Report all stopped
  - **Effort**: 15 minutes

- [ ] `monolithRestartAll()`
  - [ ] Call stopAll + sleep + startAll
  - **Effort**: 15 minutes

- [ ] `monolithStatus()`
  - [ ] Check database status
  - [ ] Check backend status
  - [ ] Check frontend status
  - [ ] Display combined report
  - **Effort**: 1 hour

### Logging

- [ ] `monolithLogsAll()`
  - [ ] Show all logs (follow)
  - [ ] Use tail -f for log files
  - **Effort**: 30 minutes

- [ ] `monolithLogDatabase()`
  - [ ] Show database logs
  - **Effort**: 20 minutes

- [ ] `monolithLogBackend()`
  - [ ] Show backend logs
  - **Effort**: 20 minutes

- [ ] `monolithLogFrontend()`
  - [ ] Show frontend logs
  - **Effort**: 20 minutes

- [ ] Helper: `getLogPath(service)`
  - [ ] Return path to {service}.log
  - **Effort**: 10 minutes

**Subtotal Phase 4**: ~3-4 hours

---

## Phase 5: Utilities - Health Checks

### Health Checks Implementation

- [ ] `healthCheckDatabase()`
  - [ ] Test PostgreSQL connection
  - [ ] Get version
  - [ ] Check essential tables
  - [ ] Report health
  - **Effort**: 1 hour

- [ ] `healthCheckBackend()`
  - [ ] Poll /health endpoint
  - [ ] Check response time
  - [ ] Verify database connectivity from backend
  - [ ] Report health
  - **Effort**: 1 hour

- [ ] `healthCheckFrontend()`
  - [ ] Poll port 5173
  - [ ] Check HTTP status
  - [ ] Verify assets available
  - [ ] Report health
  - **Effort**: 1 hour

- [ ] `healthCheckFull()`
  - [ ] Run all health checks
  - [ ] Generate combined report
  - [ ] Show timestamp
  - **Effort**: 30 minutes

**Subtotal Phase 5**: ~3.5 hours

---

## Phase 6: Utilities - Diagnostics

### System Diagnostics Implementation

- [ ] `diagnosticsDBSeparation()`
  - [ ] Check main DB exists
  - [ ] Check test DB exists
  - [ ] Verify tables are separate
  - [ ] Report issues
  - **Effort**: 1 hour

- [ ] `diagnosticsConfiguration()`
  - [ ] Check monolith.ini exists
  - [ ] Check env variables
  - [ ] Validate required settings
  - [ ] Report issues
  - **Effort**: 1 hour

- [ ] `diagnosticsFullSystem()`
  - [ ] System requirements check
  - [ ] Dependencies verification
  - [ ] Config validation
  - [ ] DB separation check
  - [ ] Generate report file
  - **Effort**: 1.5 hours

**Subtotal Phase 6**: ~3.5 hours

---

## Phase 7: Utilities - Testing (Calibration)

### Testing Commands

- [ ] `testingUnit()`
  - [ ] Determine your unit test command
  - [ ] Run backend unit tests
  - [ ] Run frontend unit tests
  - [ ] Display results
  - **Effort**: 1 hour

- [ ] `testingIntegration()`
  - [ ] Determine integration test command
  - [ ] Run API integration tests
  - [ ] Run database integration tests
  - [ ] Display results
  - **Effort**: 1 hour

- [ ] `testingSecurity()`
  - [ ] Determine security test tool
  - [ ] Run security scans
  - [ ] Display results
  - **Effort**: 1 hour

- [ ] `testingAll()`
  - [ ] Run all test suites
  - [ ] Combine results
  - [ ] Generate coverage report
  - **Effort**: 1.5 hours

**Subtotal Phase 7**: ~4.5 hours (Will be calibrated later)

---

## Phase 8: Utilities - Reporting

### Report Generation

- [ ] `reportCodeCoverage()`
  - [ ] Collect coverage data
  - [ ] Generate HTML report
  - [ ] Display summary
  - **Effort**: 1.5 hours

- [ ] `reportPerformance()`
  - [ ] Gather performance metrics
  - [ ] Generate report
  - [ ] Display graphs/tables
  - **Effort**: 1.5 hours

- [ ] `reportDatabaseSchema()`
  - [ ] Extract schema info
  - [ ] Generate ER diagram
  - [ ] Create documentation
  - **Effort**: 2 hours

- [ ] `reportSystemRequirements()`
  - [ ] Check OS requirements
  - [ ] Check dependencies
  - [ ] Check resources
  - [ ] Generate report
  - **Effort**: 1.5 hours

**Subtotal Phase 8**: ~6.5 hours

---

## Testing & QA

### Unit Testing

- [ ] Test database functions on Linux
- [ ] Test database functions on macOS
- [ ] Test backend functions on Linux
- [ ] Test backend functions on macOS
- [ ] Test frontend functions
- [ ] Test status checks
- [ ] Test log streaming
- [ ] Test error scenarios
- [ ] **Effort**: 4-6 hours

### Integration Testing

- [ ] Test complete startup flow
- [ ] Test complete shutdown flow
- [ ] Test restart operations
- [ ] Test on clean system
- [ ] Test with errors
- [ ] **Effort**: 2-3 hours

### Documentation

- [ ] Update README with Monolith info
- [ ] Update QUICK_START with real commands
- [ ] Create troubleshooting guide
- [ ] Create video tutorial (optional)
- [ ] **Effort**: 2-3 hours

**Subtotal Testing & QA**: ~8-12 hours

---

## Summary

| Phase | Item Count | Hours | Status |
|-------|-----------|-------|--------|
| 1 | Database (4) | 3-4 | ⬜ |
| 2 | Backend (7) | 4-5 | ⬜ |
| 3 | Frontend (4) | 3-4 | ⬜ |
| 4 | Status/Logs (8) | 3-4 | ⬜ |
| 5 | Health Checks (4) | 3.5 | ⬜ |
| 6 | Diagnostics (3) | 3.5 | ⬜ |
| 7 | Testing (4) | 4.5 | ⬜ |
| 8 | Reporting (4) | 6.5 | ⬜ |
| QA | Testing/Docs | 10-15 | ⬜ |
| **TOTAL** | **38** | **45-50** | ⬜ |

---

## Priority Order

### Must Have (Critical Path)
1. ✅ Phase 1: Database functions (required for any testing)
2. ✅ Phase 2: Backend functions (core functionality)
3. ✅ Phase 3: Frontend functions (core functionality)
4. ✅ Phase 4: Start/Stop/Status (essential for usability)
5. ✅ Testing & Documentation (validation)

### Should Have (Important)
6. 🔄 Phase 5: Health Checks (useful for diagnostics)
7. 🔄 Phase 6: Diagnostics (useful for setup)

### Nice to Have (Polish)
8. 🔄 Phase 7: Testing (calibration needed)
9. 🔄 Phase 8: Reporting (analysis)

---

## Implementation Strategy

### Week 1: Core Functionality
- [ ] Complete Phase 1, 2, 3
- [ ] Complete Phase 4
- [ ] Basic testing
- **Hours**: ~15-17
- **Output**: Functional Monolith Mode

### Week 2: Utilities & Polish
- [ ] Complete Phase 5, 6
- [ ] Start Phase 7 (calibration)
- [ ] Testing & QA
- **Hours**: ~15-20
- **Output**: Full Utilities menu, Health checks working

### Week 3: Calibration & Documentation
- [ ] Complete Phase 7 (tests)
- [ ] Complete Phase 8 (reports)
- [ ] Comprehensive testing
- [ ] Final documentation
- **Hours**: ~10-15
- **Output**: Complete system ready for production

---

## Notes for Implementation

### Environment Setup
- PostgreSQL must be installed on host
- Go must be in PATH
- Node.js/npm must be in PATH
- Create log directory: `~/.contract_manager/logs/`

### Process Management
- Use process groups for child processes
- Handle signals properly (SIGTERM → SIGKILL)
- Clean up resources on exit
- Store PIDs for reliability

### Error Handling
- Test PostgreSQL not installed
- Test ports already in use
- Test insufficient permissions
- Test missing dependencies
- Provide helpful error messages

### Cross-Platform Support
- Test on Linux (systemctl)
- Test on macOS (brew services)
- Document Windows/WSL limitations
- Provide fallback solutions

---

## Sign-Off Checklist

Before considering a phase complete:

- [ ] All functions implemented
- [ ] Code compiled without errors
- [ ] All functions callable from menu
- [ ] Proper error handling
- [ ] Tested on Linux
- [ ] Tested on macOS
- [ ] Documentation updated
- [ ] User can understand and use it

---

**Total Estimated Time**: 45-50 hours (spread over 2-3 weeks with proper testing)

**Highest Priority**: Phases 1-4 (core functionality)

**Next Step**: Start with Phase 1 (database functions)

