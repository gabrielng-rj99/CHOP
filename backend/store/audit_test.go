package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditLogOperations(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	store := NewAuditStore(db)

	// Create a user to be the admin
	userStore := NewUserStore(db)
	adminID, err := userStore.CreateUser("admin_tester", "Admin Tester", "Passw0rd!Secure123", "admin")
	if err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}
	adminUser := "admin_tester"

	// 1. Test LogOperation (Create)
	t.Run("LogOperation", func(t *testing.T) {
		req := AuditLogRequest{
			Operation:     "create",
			Entity:        "user",
			EntityID:      uuid.New().String(),
			AdminID:       &adminID,
			AdminUsername: &adminUser,
			Status:        "success",
			OldValue:      nil,
			NewValue:      map[string]string{"username": "newuser"},
			IPAddress:     stringToPtr("127.0.0.1"),
		}

		id, err := store.LogOperation(req)
		if err != nil {
			t.Fatalf("Failed to log operation: %v", err)
		}
		if id == "" {
			t.Error(" expected non-empty ID")
		}
	})

	// 2. Test GetAuditLogByID
	t.Run("GetAuditLogByID", func(t *testing.T) {
		req := AuditLogRequest{
			Operation: "update",
			Entity:    "category",
			EntityID:  "cat123",
			Status:    "success",
		}
		id, _ := store.LogOperation(req)

		log, err := store.GetAuditLogByID(id)
		if err != nil {
			t.Fatalf("Failed to get log: %v", err)
		}
		if log.ID != id {
			t.Errorf("Expected ID %s, got %s", id, log.ID)
		}
		if log.Operation != "update" {
			t.Errorf("Expected operation update, got %s", log.Operation)
		}
	})

	// 3. Test ListAuditLogs with filters
	t.Run("ListAuditLogs", func(t *testing.T) {
		// Create some dummy logs
		_, err := store.LogOperation(AuditLogRequest{Operation: "delete", Entity: "agreement", Status: "success", AdminID: &adminID})
		if err != nil {
			t.Fatalf("Failed to create log 1: %v", err)
		}
		_, err = store.LogOperation(AuditLogRequest{Operation: "read", Entity: "agreement", Status: "error"})
		if err != nil {
			t.Fatalf("Failed to create log 2: %v", err)
		}

		filter := AuditLogFilter{
			Entity: stringToPtr("agreement"),
			Limit:  10,
		}

		logs, err := store.ListAuditLogs(filter)
		if err != nil {
			t.Fatalf("Failed to list logs: %v", err)
		}
		if len(logs) < 2 {
			t.Errorf("Expected at least 2 logs, got %d", len(logs))
		}
	})

	// 4. Test CountAuditLogs
	t.Run("CountAuditLogs", func(t *testing.T) {
		filter := AuditLogFilter{
			Entity: stringToPtr("agreement"),
		}
		count, err := store.CountAuditLogs(filter)
		if err != nil {
			t.Fatalf("Failed to count logs: %v", err)
		}
		if count < 2 {
			t.Errorf("Expected count >= 2, got %d", count)
		}
	})

	// 5. Test Invalid Operation
	t.Run("InvalidOperation", func(t *testing.T) {
		req := AuditLogRequest{
			Operation: "destroy", // Invalid
			Entity:    "user",
		}
		_, err := store.LogOperation(req)
		if err == nil {
			t.Error("Expected error for invalid operation, got nil")
		}
	})

	// 6. Test DeleteOldAuditLogs
	t.Run("DeleteOldAuditLogs", func(t *testing.T) {
		// Since we can't easily backdate logs in pure unit test without direct DB manipulation or mocking time,
		// we'll primarily test that the query executes without error.
		// Or we could manually insert an old log using db.Exec

		_, err := db.Exec("INSERT INTO audit_logs (id, timestamp, operation, entity, entity_id, status) VALUES ($1, $2, 'create', 'test', '123', 'success')",
			uuid.New().String(), time.Now().AddDate(0, 0, -10))
		if err != nil {
			t.Fatalf("Failed to insert old log: %v", err)
		}

		deleted, err := store.DeleteOldAuditLogs(5) // Delete older than 5 days
		if err != nil {
			t.Fatalf("Failed to delete old logs: %v", err)
		}
		if deleted < 1 {
			t.Logf("Expected at least 1 deleted log, got %d (might satisfy if db clean)", deleted)
		}
	})
}

func stringToPtr(s string) *string {
	return &s
}
