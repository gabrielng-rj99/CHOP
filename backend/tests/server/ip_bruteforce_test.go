package server_test

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Estrutura para simular a tabela de tentativas por IP
type IPLock struct {
	IP             string
	FailedAttempts int
	LockLevel      int
	LockedUntil    time.Time
}

// SetupTestDBIP inicializa um banco SQLite3 para testes de IP
func SetupTestDBIP(t *testing.T) (*sql.DB, func()) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to get caller info")
	}
	backendDir := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
	dbDir := filepath.Join(backendDir, "tests", "database")
	dbPath := filepath.Join(dbDir, "test_ip.db")

	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatalf("failed to create tests/database directory: %v", err)
	}
	if _, err := os.Stat(dbPath); err == nil {
		_ = os.Remove(dbPath)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Cria tabela de tentativas por IP
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS login_attempts (
			ip_address TEXT PRIMARY KEY,
			failed_attempts INTEGER DEFAULT 0,
			lock_level INTEGER DEFAULT 0,
			locked_until DATETIME
		)
	`)
	if err != nil {
		db.Close()
		t.Fatalf("failed to create login_attempts table: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.Remove(dbPath)
	}

	return db, cleanup
}

// Funções auxiliares para manipular tentativas por IP no banco
func getIPLockDB(db *sql.DB, ip string) *IPLock {
	var failedAttempts, lockLevel int
	var lockedUntil sql.NullTime
	row := db.QueryRow("SELECT failed_attempts, lock_level, locked_until FROM login_attempts WHERE ip_address = ?", ip)
	err := row.Scan(&failedAttempts, &lockLevel, &lockedUntil)
	if err == sql.ErrNoRows {
		// Insere registro novo
		_, _ = db.Exec("INSERT INTO login_attempts (ip_address, failed_attempts, lock_level) VALUES (?, 0, 0)", ip)
		return &IPLock{IP: ip}
	} else if err != nil {
		return &IPLock{IP: ip}
	}
	lock := IPLock{IP: ip, FailedAttempts: failedAttempts, LockLevel: lockLevel}
	if lockedUntil.Valid {
		lock.LockedUntil = lockedUntil.Time
	}
	return &lock
}

func updateIPLockDB(db *sql.DB, lock *IPLock) {
	_, _ = db.Exec("UPDATE login_attempts SET failed_attempts = ?, lock_level = ?, locked_until = ? WHERE ip_address = ?",
		lock.FailedAttempts, lock.LockLevel, lock.LockedUntil, lock.IP)
}

var bruteForceLevels = []struct {
	attempts int
	duration time.Duration
}{
	{5, time.Minute},
	{3, 5 * time.Minute},
	{3, 15 * time.Minute},
	{3, 30 * time.Minute},
	{3, 60 * time.Minute},
	{3, 120 * time.Minute},
	{3, 240 * time.Minute},
	{3, 480 * time.Minute},
	{3, 1440 * time.Minute}, // 24h
}

func TestIPBruteForceBlocking_SQLite(t *testing.T) {
	db, cleanup := SetupTestDBIP(t)
	defer cleanup()

	ip := "192.168.1.100"

	// Simula tentativas de login inválidas
	for i := 0; i < 5; i++ {
		t.Logf("Tentativa %d: login inválido, esperando não bloquear", i+1)
		resp := simulateLoginDB(db, ip, false)
		t.Logf("Tentativa %d: resp.Code=%d", i+1, resp.Code)
		if resp.Code == http.StatusTooManyRequests {
			t.Fatalf("IP bloqueado prematuramente na tentativa %d", i+1)
		}
	}

	// 6ª tentativa deve bloquear por 1 minuto
	t.Log("Tentativa 6: deve bloquear por 1 minuto")
	resp := simulateLoginDB(db, ip, false)
	t.Logf("Tentativa 6: resp.Code=%d", resp.Code)
	if resp.Code != http.StatusTooManyRequests {
		t.Errorf("Esperado bloqueio por IP após 5 tentativas, mas não ocorreu")
	}
	lock := getIPLockDB(db, ip)
	t.Logf("Lock após 6ª tentativa: %+v", lock)
	if time.Until(lock.LockedUntil) < time.Minute-5*time.Second {
		t.Errorf("Tempo de bloqueio por IP incorreto: %v", time.Until(lock.LockedUntil))
	}

	// Simula passagem de tempo (desbloqueio)
	t.Log("Simulando passagem de tempo para desbloquear IP")
	lock.LockedUntil = time.Now().Add(-time.Second)
	updateIPLockDB(db, lock)

	// Mais 3 tentativas para subir de nível (5min)
	for i := 0; i < 3; i++ {
		t.Logf("Tentativa nível 2 - %d: login inválido, esperando não bloquear até a 3ª", i+1)
		resp := simulateLoginDB(db, ip, false)
		t.Logf("Tentativa nível 2 - %d: resp.Code=%d", i+1, resp.Code)
		if resp.Code == http.StatusTooManyRequests && i < 2 {
			t.Fatalf("IP bloqueado prematuramente no nível 2 na tentativa %d", i+1)
		}
	}
	t.Log("Tentativa nível 2 - 4: deve bloquear por 5 minutos")
	resp = simulateLoginDB(db, ip, false)
	t.Logf("Tentativa nível 2 - 4: resp.Code=%d", resp.Code)
	if resp.Code != http.StatusTooManyRequests {
		t.Errorf("Esperado bloqueio por IP após 3 tentativas no nível 2")
	}
	lock = getIPLockDB(db, ip)
	t.Logf("Lock após nível 2: %+v", lock)
	if time.Until(lock.LockedUntil) < 5*time.Minute-5*time.Second {
		t.Errorf("Tempo de bloqueio por IP incorreto no nível 2: %v", time.Until(lock.LockedUntil))
	}

	// Testa desbloqueio após sucesso
	t.Log("Simulando passagem de tempo para desbloquear IP (nível 2)")
	lock.LockedUntil = time.Now().Add(-time.Second)
	updateIPLockDB(db, lock)
	t.Log("Tentativa de login bem-sucedido para resetar tentativas do IP")
	resp = simulateLoginDB(db, ip, true)
	t.Logf("Tentativa sucesso: resp.Code=%d", resp.Code)
	if resp.Code == http.StatusUnauthorized {
		t.Errorf("Login deveria ter sucesso e resetar tentativas do IP")
	}
	lock = getIPLockDB(db, ip)
	t.Logf("Lock após sucesso: %+v", lock)
	if lock.FailedAttempts != 0 || lock.LockLevel != 0 || !lock.LockedUntil.IsZero() {
		t.Errorf("Tentativas do IP não foram resetadas após sucesso: %+v", lock)
	}
}

// Simula o endpoint de login, usando a lógica de bloqueio por IP com SQLite
func simulateLoginDB(db *sql.DB, ip string, success bool) *httptest.ResponseRecorder {
	reqBody := map[string]string{
		"username": "testuser",
		"password": "wrongpassword",
	}
	if success {
		reqBody["password"] = "rightpassword"
	}
	req := httptest.NewRequest("POST", "/api/login", nil)
	req.RemoteAddr = ip

	rr := httptest.NewRecorder()

	ipLock := getIPLockDB(db, ip)
	now := time.Now()
	if !ipLock.LockedUntil.IsZero() && now.Before(ipLock.LockedUntil) {
		http.Error(rr, fmt.Sprintf("Este IP está bloqueado até %s por múltiplas tentativas.", ipLock.LockedUntil.Format(time.RFC1123)), http.StatusTooManyRequests)
		return rr
	}

	if !success {
		ipLock.FailedAttempts++
		level := ipLock.LockLevel
		if level >= len(bruteForceLevels) {
			ipLock.LockedUntil = now.Add(365 * 24 * time.Hour) // bloqueio manual
		} else {
			limit := bruteForceLevels[level].attempts
			if ipLock.FailedAttempts >= limit {
				ipLock.LockLevel++
				if ipLock.LockLevel >= len(bruteForceLevels) {
					ipLock.LockedUntil = now.Add(365 * 24 * time.Hour)
				} else {
					ipLock.LockedUntil = now.Add(bruteForceLevels[ipLock.LockLevel].duration)
				}
				ipLock.FailedAttempts = 0
			}
		}
		updateIPLockDB(db, ipLock)
		http.Error(rr, "Usuário ou senha inválidos", http.StatusUnauthorized)
		return rr
	}

	// Sucesso: zera tentativas do IP
	ipLock.FailedAttempts = 0
	ipLock.LockLevel = 0
	ipLock.LockedUntil = time.Time{}
	updateIPLockDB(db, ipLock)
	rr.WriteHeader(http.StatusOK)
	rr.Write([]byte(`{"id":"testid","username":"testuser"}`))
	return rr
}
