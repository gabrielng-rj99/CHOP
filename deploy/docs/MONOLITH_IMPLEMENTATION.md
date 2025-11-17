# Monolith Mode Implementation Guide

This document provides detailed instructions for implementing the Monolith Mode functions in the Deploy Manager CLI.

## Overview

Monolith Mode runs services directly on your host machine without containerization:
- **PostgreSQL**: Native system service
- **Backend**: Go application running with `go run`
- **Frontend**: Node.js dev server running with `npm run dev`

## Architecture

```
┌──────────────────────────────────────┐
│      Host Machine (Linux/macOS)      │
├──────────────────────────────────────┤
│                                      │
│  Process 1: PostgreSQL Service       │
│  - Port: 5432                        │
│  - Managed by: systemctl/brew        │
│                                      │
│  Process 2: Backend (go run)         │
│  - Port: 3000                        │
│  - PID: stored for management        │
│  - Logs: to file                     │
│                                      │
│  Process 3: Frontend (npm dev)       │
│  - Port: 5173                        │
│  - Auto hot-reload                   │
│  - Logs: to file                     │
│                                      │
└──────────────────────────────────────┘
```

## Implementation Checklist

### Phase 1: Database Management Functions

#### Function: `monolithStartDatabase()`
**Purpose**: Start PostgreSQL service on host machine

**Implementation Steps**:
1. Detect OS (Linux vs macOS)
2. Start appropriate service:
   - **Linux**: `sudo systemctl start postgresql`
   - **macOS**: `brew services start postgresql`
3. Wait for connection readiness (retry with timeout)
4. Test connection: `psql -U postgres -c "SELECT 1"`
5. Report success/failure

**Pseudo-code**:
```go
func monolithStartDatabase() {
    fmt.Println("\n▶️  Starting PostgreSQL...")
    
    // Detect OS
    if runtime.GOOS == "linux" {
        cmd := exec.Command("sudo", "systemctl", "start", "postgresql")
        if err := cmd.Run(); err != nil {
            fmt.Printf("❌ Failed to start PostgreSQL: %v\n", err)
        }
    } else if runtime.GOOS == "darwin" {
        cmd := exec.Command("brew", "services", "start", "postgresql")
        if err := cmd.Run(); err != nil {
            fmt.Printf("❌ Failed to start PostgreSQL: %v\n", err)
        }
    }
    
    // Wait for readiness
    for i := 0; i < 10; i++ {
        cmd := exec.Command("psql", "-U", "postgres", "-c", "SELECT 1")
        if err := cmd.Run(); err == nil {
            fmt.Println("✅ PostgreSQL is running!")
            break
        }
        time.Sleep(1 * time.Second)
    }
    
    waitForEnter()
}
```

**Key Considerations**:
- May require sudo password on Linux
- macOS uses Homebrew for service management
- Test connectivity before reporting success
- Timeout if service doesn't start within 10 seconds

---

#### Function: `monolithStopDatabase()`
**Purpose**: Stop PostgreSQL service

**Implementation Steps**:
1. Detect OS
2. Stop service:
   - **Linux**: `sudo systemctl stop postgresql`
   - **macOS**: `brew services stop postgresql`
3. Verify it's stopped (check connection fails)
4. Report success

**Key Considerations**:
- May require sudo password
- Must wait for graceful shutdown
- Verify stopped before continuing

---

#### Function: `monolithRestartDatabase()`
**Purpose**: Restart PostgreSQL service

**Implementation Steps**:
1. Call `monolithStopDatabase()`
2. Wait 2 seconds
3. Call `monolithStartDatabase()`

---

#### Function: `monolithDatabaseStatus()`
**Purpose**: Check if PostgreSQL is running and accessible

**Implementation Steps**:
1. Test connection: `psql -U postgres -c "SELECT version()"`
2. If successful:
   - Get version info
   - Get list of databases
   - Get database sizes
3. Report status and details
4. If failed, suggest starting it

**Pseudo-code**:
```go
func monolithDatabaseStatus() {
    fmt.Println("\n📊 PostgreSQL status:")
    
    cmd := exec.Command("psql", "-U", "postgres", "-c", "SELECT version();")
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        fmt.Println("❌ PostgreSQL is not running or not accessible")
        fmt.Println("\nTry starting it:")
        fmt.Println("Menu → 2 (Monolith) → 21 (Start database)")
    } else {
        fmt.Printf("✅ PostgreSQL is running:\n%s\n", output)
        // Get more details
    }
    
    waitForEnter()
}
```

---

### Phase 2: Backend Management Functions

#### Function: `monolithStartBackend()`
**Purpose**: Start Go API server

**Implementation Steps**:
1. Get project root
2. Change to `backend/` directory
3. Start `go run ./cmd/api` in background
4. Redirect stdout/stderr to log file: `backend.log`
5. Store PID for later management
6. Wait for readiness (retry hitting `/health` endpoint)
7. Report success

**Pseudo-code**:
```go
func monolithStartBackend() {
    fmt.Println("\n▶️  Starting Backend (go run ./cmd/api)...")
    
    projectRoot, err := getProjectRoot()
    if err != nil {
        fmt.Printf("❌ Error: %v\n", err)
        waitForEnter()
        return
    }
    
    backendDir := filepath.Join(projectRoot, "backend")
    logFile, _ := os.Create(filepath.Join(projectRoot, "backend.log"))
    defer logFile.Close()
    
    cmd := exec.Command("go", "run", "./cmd/api")
    cmd.Dir = backendDir
    cmd.Stdout = logFile
    cmd.Stderr = logFile
    cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
    
    if err := cmd.Start(); err != nil {
        fmt.Printf("❌ Failed to start backend: %v\n", err)
    } else {
        // Save PID
        savePID("backend", cmd.Process.Pid)
        
        // Wait for readiness
        for i := 0; i < 30; i++ {
            resp, err := http.Get("http://localhost:3000/health")
            if err == nil && resp.StatusCode == 200 {
                fmt.Println("✅ Backend is running on http://localhost:3000")
                break
            }
            time.Sleep(1 * time.Second)
        }
    }
    
    waitForEnter()
}
```

**Key Considerations**:
- Use `SysProcAttr` for process group (needed for killing child processes)
- Create log file to capture output
- Save PID for later management
- Test `/health` endpoint for readiness
- Timeout after 30 seconds

---

#### Function: `monolithStopBackend()`
**Purpose**: Stop the Go API server

**Implementation Steps**:
1. Load saved PID from file or process list
2. Kill process group (not just PID)
3. Wait for graceful shutdown
4. Force kill if still running after 5 seconds
5. Report success

**Pseudo-code**:
```go
func monolithStopBackend() {
    fmt.Println("\n⏹️  Stopping Backend...")
    
    pid := loadPID("backend")
    if pid == 0 {
        // Try to find by port
        pid = findProcessByPort(3000)
    }
    
    if pid > 0 {
        // Kill process group
        syscall.Kill(-pid, syscall.SIGTERM)
        
        // Wait for graceful shutdown
        time.Sleep(2 * time.Second)
        
        // Force kill if still running
        syscall.Kill(-pid, syscall.SIGKILL)
        fmt.Println("✅ Backend stopped!")
    } else {
        fmt.Println("ℹ️  Backend is not running")
    }
    
    waitForEnter()
}
```

**Key Considerations**:
- Store PID in a temp file for later retrieval
- Kill process group, not individual process
- Graceful shutdown with SIGTERM first
- Force kill with SIGKILL if needed
- Handle case where process already dead

---

#### Function: `monolithRestartBackend()`
**Purpose**: Restart the Go API server

**Implementation Steps**:
1. Call `monolithStopBackend()`
2. Wait 2 seconds
3. Call `monolithStartBackend()`

---

### Phase 3: Frontend Management Functions

#### Function: `monolithStartFrontend()`
**Purpose**: Start Node.js dev server

**Implementation Steps**:
1. Get project root
2. Change to `frontend/` directory
3. Start `npm run dev` in background
4. Redirect output to log file: `frontend.log`
5. Store PID
6. Wait for readiness (check port 5173)
7. Report success

**Similar to backend but**:
- Uses `npm run dev` instead of `go run`
- Port is 5173
- May need to handle npm's output parsing
- Frontend has automatic hot reload

---

#### Function: `monolithStopFrontend()`
**Purpose**: Stop the Node.js dev server

**Implementation Steps**:
1. Load saved PID
2. Kill process group gracefully
3. Force kill if needed
4. Report success

---

#### Function: `monolithRestartFrontend()`
**Purpose**: Restart the Node.js dev server

**Implementation Steps**:
1. Call `monolithStopFrontend()`
2. Wait 2 seconds
3. Call `monolithStartFrontend()`

---

### Phase 4: Service Status and Logs Functions

#### Function: `monolithStatus()`
**Purpose**: Check status of all services

**Implementation Steps**:
1. Check PostgreSQL (try connection)
2. Check Backend (check port 3000 and PID)
3. Check Frontend (check port 5173 and PID)
4. Report status for all three

**Output Example**:
```
PostgreSQL: ✅ Running (localhost:5432)
Backend:    ✅ Running (localhost:3000, PID: 12345)
Frontend:   ✅ Running (localhost:5173, PID: 12346)
```

---

#### Function: `monolithLogsAll()`, `monolithLogDatabase()`, `monolithLogBackend()`, `monolithLogFrontend()`
**Purpose**: Display service logs

**Implementation Options**:

**Option A: File-based (Simpler)**
```go
func monolithLogBackend() {
    fmt.Println("\n🔍 Backend logs (press Ctrl+C to exit):\n")
    cmd := exec.Command("tail", "-f", "backend.log")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Run()
    waitForEnter()
}
```

**Option B: Real-time from process (More Complex)**
- Capture output while process is running
- Requires storing stdout/stderr pipes

**Key Considerations**:
- Create log files on startup
- Allow following logs in real-time
- Ctrl+C should exit log viewer
- Show helpful message about finding log files

---

### Phase 5: All-in-One Functions

#### Function: `monolithStartAll()`
**Purpose**: Start all services in order

**Implementation Steps**:
1. Start PostgreSQL
2. Wait 3 seconds
3. Start Backend
4. Wait 2 seconds
5. Start Frontend
6. Wait 2 seconds
7. Report all services running
8. Display access URLs

---

#### Function: `monolithStopAll()`
**Purpose**: Stop all services

**Implementation Steps**:
1. Stop Frontend
2. Stop Backend
3. Stop PostgreSQL
4. Report all stopped

---

#### Function: `monolithRestartAll()`
**Purpose**: Restart all services

**Implementation Steps**:
1. Call `monolithStopAll()`
2. Wait 3 seconds
3. Call `monolithStartAll()`

---

## Helper Functions Needed

### 1. Process Management
```go
func savePID(service string, pid int) {
    // Save to file: /tmp/contract_manager_{service}.pid
}

func loadPID(service string) int {
    // Load from file
    // Return 0 if file doesn't exist
}

func findProcessByPort(port int) int {
    // Use: lsof -ti :{port}
    // Return PID or 0
}

func isProcessRunning(pid int) bool {
    // Check if process exists
    // Use: syscall.Kill(pid, 0)
}
```

### 2. Health Checks
```go
func waitForDatabaseReady(timeout int) bool {
    // Try psql connection
    // Retry until timeout
}

func waitForAPIReady(timeout int) bool {
    // Poll http://localhost:3000/health
    // Retry until timeout
}

func waitForFrontendReady(timeout int) bool {
    // Poll http://localhost:5173
    // Retry until timeout
}
```

### 3. Log Management
```go
func getLogPath(service string) string {
    // Return path to {service}.log
}

func clearLogFile(service string) {
    // Truncate log file
}
```

---

## Configuration Considerations

### Environment Variables
Backend may need:
```
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=<password>
DB_NAME=contract_manager_db
API_PORT=3000
```

Frontend may need:
```
VITE_API_URL=http://localhost:3000
```

Load from `deploy/config/monolith.ini` or system environment.

---

## Error Handling Strategy

### Database Errors
```
"Connection refused" → PostgreSQL not running
→ Suggest: "Start PostgreSQL first: Menu → 2 → 21"

"Permission denied" → sudo needed
→ Suggest: "May require password entry"

"Role does not exist" → postgres user not found
→ Suggest: "PostgreSQL not properly installed"
```

### Backend Errors
```
"Port 3000 already in use" → Another process using it
→ Suggest: "Kill process: lsof -ti :3000 | xargs kill -9"

"go: command not found" → Go not installed
→ Suggest: "Install Go 1.21+"

"missing go.mod" → Not in backend directory
→ Suggest: "Run from project root: cd project-root/deploy"
```

### Frontend Errors
```
"npm: command not found" → Node.js not installed
→ Suggest: "Install Node.js 18+"

"node_modules not found" → Dependencies missing
→ Suggest: "Run: cd frontend && npm install"
```

---

## Testing the Implementation

### Test Database Functions
```bash
./bin/deploy-manager
→ 2 (Monolith)
→ 21 (Start database)
# Should show: "✅ PostgreSQL is running!"

→ 24 (Database status)
# Should show version and database info

→ 22 (Stop database)
# Should show: "✅ PostgreSQL stopped!"
```

### Test Backend Functions
```bash
./bin/deploy-manager
→ 2 (Monolith)
→ 11 (Start all) or 25 (Start backend)
# Should show: "✅ Backend is running on http://localhost:3000"

→ 33 (View backend logs)
# Should show live logs

→ 26 (Stop backend)
# Should stop the process
```

### Test Frontend Functions
```bash
./bin/deploy-manager
→ 2 (Monolith)
→ 28 (Start frontend)
# Should show: "✅ Frontend is running on http://localhost:5173"

→ 30 (Restart frontend)
# Should restart cleanly
```

---

## Best Practices

1. **Process Management**
   - Always use process groups for child process management
   - Store PIDs for reliable shutdown
   - Use SIGTERM first, then SIGKILL
   - Clean up PID files after shutdown

2. **Log Management**
   - Append to log files, don't truncate
   - Show last 50 lines on startup
   - Implement log rotation (keep recent logs)
   - Clear logs on fresh start

3. **Error Messages**
   - Be specific about what failed
   - Suggest remediation steps
   - Show relevant system commands
   - Log errors to debug file

4. **User Experience**
   - Show clear status messages
   - Use consistent emoji indicators
   - Provide helpful hints
   - Don't require typing complicated commands

5. **Robustness**
   - Handle already-running services gracefully
   - Handle already-stopped services gracefully
   - Detect port conflicts
   - Verify dependencies are installed

---

## Timeline & Effort Estimates

| Phase | Functions | Effort | Time |
|-------|-----------|--------|------|
| 1 | Database (4) | Low | 1-2 hours |
| 2 | Backend (4) | Medium | 2-3 hours |
| 3 | Frontend (4) | Medium | 2-3 hours |
| 4 | Logs/Status (5) | Low-Medium | 1-2 hours |
| 5 | All-in-One (3) | Low | 30 min |
| **Total** | **20 functions** | **Medium** | **7-11 hours** |

---

## Integration Checklist

- [ ] Phase 1: Database functions working
- [ ] Phase 2: Backend functions working
- [ ] Phase 3: Frontend functions working
- [ ] Phase 4: Logs and status working
- [ ] Phase 5: All-in-one functions working
- [ ] Test on Linux
- [ ] Test on macOS
- [ ] Test error scenarios
- [ ] Update documentation
- [ ] Add to CI/CD pipeline

---

## Future Enhancements

1. **Process Monitoring**
   - Automatic restart on crash
   - Resource usage alerts
   - Health check monitoring

2. **Log Management**
   - Log rotation
   - Log file cleanup
   - Log analysis

3. **Configuration**
   - Hot-reload config changes
   - Multiple environment profiles
   - Secrets management

4. **Performance**
   - Profiling integration
   - Benchmark tools
   - Performance tracking

---

## References

- Go `os/exec` package: https://pkg.go.dev/os/exec
- Go `syscall` package: https://pkg.go.dev/syscall
- PostgreSQL service management: https://www.postgresql.org/docs/current/starting.html
- systemctl documentation: https://www.freedesktop.org/software/systemd/man/systemctl.html
- brew services: https://brew.sh/
